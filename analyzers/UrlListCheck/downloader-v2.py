#!/usr/bin/env python3
"""
downloader.py — robust file downloader with TLS controls, sane headers,
filename sanitization, size guardrails, and optional final permissions.

CLI examples:
  python downloader.py --url https://example.com/latest.txt --dest ./out/
  python downloader.py --url https://example.com/big.bin --dest ./b.bin --max-bytes 100m
  python downloader.py --url https://example.com/selfsigned --dest ./s.bin --ca-cert ./my-ca.pem
  python downloader.py --url https://example.com/file --dest ./file --no-verify
  python downloader.py --url https://example.com/file --dest ./file --mode 0600

Library:
  from downloader import download_file
  ok = download_file(
      url="https://example.com/file",
      dest_path="/tmp/file",
      verify_tls=True,
      ca_cert=None,            # path or PEM string; only used if verify_tls=True
      timeout=60,
      max_bytes=None,          # e.g., 10 * 1024 * 1024 for 10 MiB
      user_agent="my-app/1.0", # optional; default provided
      file_mode=0o644,         # set final perms after atomic replace; set None to skip chmod
  )
  print(ok)  # True/False
"""

from __future__ import annotations

import argparse
import os
import re
import ssl
import sys
import tempfile
import zlib
from typing import Optional
from urllib import request, error, parse

_CHUNK_SIZE = 1024 * 1024  # 1 MiB
_DEFAULT_UA = "python-downloader/1.2 (+no-tracking)"
_SUPPORTED_ENCODINGS = {"identity", "gzip", "x-gzip", "deflate"}


# ---------- helpers ----------

def _looks_like_pem(text: str) -> bool:
    return "BEGIN CERTIFICATE" in text and "END CERTIFICATE" in text


def _prepare_ssl_context(verify_tls: bool, ca_cert_path: Optional[str]) -> Optional[ssl.SSLContext]:
    if not verify_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if ca_cert_path:
        return ssl.create_default_context(cafile=ca_cert_path)
    return ssl.create_default_context()


def _parse_content_disposition_filename(cd_header: str) -> Optional[str]:
    """
    Extract a filename from Content-Disposition.
    Supports RFC5987 filename*=UTF-8''... and fallback filename="...".
    """
    if not cd_header:
        return None
    parts = [p.strip() for p in cd_header.split(";")]
    # RFC5987: filename*=UTF-8''percent-encoded
    for p in parts:
        if p.lower().startswith("filename*="):
            try:
                _, v = p.split("=", 1)
                v = v.strip().strip('"').strip("'")
                if "''" in v:
                    _, enc_name = v.split("''", 1)
                    return parse.unquote(enc_name)
            except Exception:
                pass
    # Fallback: filename="name"
    for p in parts:
        if p.lower().startswith("filename="):
            try:
                _, v = p.split("=", 1)
                return v.strip().strip('"')
            except Exception:
                pass
    return None


def _sanitize_filename(name: str, default: str = "download") -> str:
    """
    Belt‑and‑suspenders: collapse to a safe basename, strip separators and
    control chars, avoid traversal, and dodge Windows reserved names.
    """
    if not name:
        return default

    # Trim whitespace/quotes/NULs
    name = name.strip().strip('"\'' ).replace("\x00", "")

    # Strip drive letters like C:\ and leading separators
    name = re.sub(r"^[a-zA-Z]:[\\/]+", "", name)
    name = name.lstrip("/\\")
    # Normalize to forward slashes and take basename
    name = os.path.basename(name.replace("\\", "/"))

    # Remove path separators & control characters
    name = "".join(c if (c.isprintable() and c not in "/\\") else "_" for c in name)

    # Avoid empty / dot / dotdot
    if name in {"", ".", ".."}:
        name = default

    # Avoid Windows reserved basenames
    stem = name.split(".")[0].upper()
    reserved = {
        "CON", "PRN", "AUX", "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }
    if stem in reserved:
        name = f"_{name}"

    # Keep it reasonable
    return name[:255] or default


def _resolve_destination_path(dest_path: str, url: str, cd_header: Optional[str]) -> str:
    """
    If dest_path is a directory (exists or ends with separator), infer a filename
    from sanitized Content-Disposition or URL basename; else use dest_path.
    """
    dir_hint = (
        dest_path.endswith(os.sep)
        or (os.altsep and dest_path.endswith(os.altsep))
        or (os.path.exists(dest_path) and os.path.isdir(dest_path))
    )
    if not dir_hint:
        return dest_path

    name = None
    if cd_header:
        cd_name = _parse_content_disposition_filename(cd_header)
        if cd_name:
            name = _sanitize_filename(cd_name)

    if not name:
        url_base = os.path.basename(parse.urlparse(url).path) or "download"
        name = _sanitize_filename(url_base)

    return os.path.join(dest_path, name)


def _parse_size_to_bytes(s: str) -> int:
    """
    Accepts raw bytes (e.g., "12345") or human-ish ("10k", "100m", "1g", optional 'b'/'ib').
    Uses binary multiples (KiB/MiB/GiB).
    """
    s = s.strip().lower()
    m = re.fullmatch(r"(\d+)\s*([kmgt])?(i?b)?", s)
    if not m:
        # try plain int
        return int(s)
    val = int(m.group(1))
    unit = m.group(2)
    mult = {"k": 1024, "m": 1024 ** 2, "g": 1024 ** 3, "t": 1024 ** 4}
    return val * (mult[unit] if unit else 1)


def _parse_mode(s: str) -> int:
    s = s.strip().lower()
    if s.startswith("0o"):
        s = s[2:]
    if s.startswith("0") and s != "0":
        # allow "0644"
        s = s.lstrip("0") or "0"
    return int(s, 8)


# ---------- core ----------

def download_file(
    url: str,
    dest_path: str,
    verify_tls: bool = True,
    ca_cert: Optional[str] = None,
    timeout: int = 60,
    max_bytes: Optional[int] = None,
    user_agent: Optional[str] = _DEFAULT_UA,
    file_mode: Optional[int] = 0o644,
) -> bool:
    """
    Download `url` to `dest_path`, honoring TLS verification settings.
    - Sends Accept-Encoding: identity to avoid on-the-fly gzip.
    - If a server still responds with gzip/deflate, auto-decompress before writing.
    - If dest_path is a directory, infers a sanitized filename from Content-Disposition or URL.
    - Streams to a temp file and atomically renames.
    - If max_bytes is set, fails fast (using Content-Length when trustworthy) and enforces while streaming.
    - If file_mode is set, applies os.chmod after replace.

    Returns True on success, False otherwise.
    """
    tmp_ca_file = None
    tmp_output = None

    try:
        scheme = parse.urlparse(url).scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"Unsupported URL scheme: {scheme}. Only http and https are allowed.")

        # If the ca_cert is a PEM string, write to a temp file so ssl can load it
        ca_cert_path: Optional[str] = None
        if verify_tls and ca_cert:
            if os.path.exists(ca_cert):
                ca_cert_path = ca_cert
            elif _looks_like_pem(ca_cert):
                fd, tmp_ca_file = tempfile.mkstemp(prefix="ca_", suffix=".pem")
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(ca_cert)
                ca_cert_path = tmp_ca_file
            else:
                raise ValueError("ca_cert must be a path to a PEM file or a PEM-formatted certificate string.")

        context = _prepare_ssl_context(verify_tls=verify_tls, ca_cert_path=ca_cert_path)

        headers = {
            "User-Agent": user_agent or _DEFAULT_UA,
            "Accept-Encoding": "identity",  # store plain text; we’ll still handle gzip/deflate if sent anyway
            "Connection": "close",
        }
        req = request.Request(url, method="GET", headers=headers)

        with request.urlopen(req, timeout=timeout, context=context) as resp:
            cd = resp.headers.get("Content-Disposition", "")
            final_path = _resolve_destination_path(dest_path, url, cd)
            target_dir = os.path.dirname(final_path) or "."
            os.makedirs(target_dir, exist_ok=True)

            # Determine encoding (normalize + support single encoding)
            enc_header = resp.headers.get("Content-Encoding", "")
            encs = [e.strip().lower() for e in enc_header.split(",") if e.strip()]
            # Permit no encoding or identity; support single gzip/x-gzip/deflate; reject others or chains.
            if len(encs) == 0:
                encoding = "identity"
            elif len(encs) == 1 and encs[0] in _SUPPORTED_ENCODINGS:
                encoding = encs[0]
            else:
                raise ValueError(f"Unsupported Content-Encoding: {enc_header or '<multiple/unknown>'}")

            # Size guardrail (header-based, only trustworthy if identity)
            cl = resp.headers.get("Content-Length")
            if max_bytes is not None and cl and encoding in {"identity"}:
                try:
                    if int(cl) > max_bytes:
                        raise ValueError(f"Remote file too large: {cl} bytes > max_bytes={max_bytes}")
                except ValueError:
                    # If Content-Length is malformed, just ignore and fall back to streaming guard.
                    pass

            # Stream download (with optional decompression)
            total_written = 0
            with tempfile.NamedTemporaryFile(delete=False, dir=target_dir) as tmp:
                tmp_output = tmp.name

                if encoding in {"gzip", "x-gzip", "deflate"}:
                    # Prepare a streaming decompressor
                    if encoding in {"gzip", "x-gzip"}:
                        decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)  # gzip wrapper
                        is_deflate = False
                    else:
                        decomp = zlib.decompressobj()  # zlib-wrapped deflate (RFC 7230)
                        is_deflate = True
                        deflate_first_chunk = True

                    while True:
                        chunk = resp.read(_CHUNK_SIZE)
                        if not chunk:
                            break
                        try:
                            decoded = decomp.decompress(chunk)
                        except zlib.error:
                            # Some servers send raw deflate; retry with raw mode on first chunk
                            if is_deflate and deflate_first_chunk:
                                decomp = zlib.decompressobj(-zlib.MAX_WBITS)
                                decoded = decomp.decompress(chunk)
                            else:
                                raise
                        finally:
                            if is_deflate:
                                deflate_first_chunk = False

                        if decoded:
                            if max_bytes is not None and total_written + len(decoded) > max_bytes:
                                raise ValueError("Exceeded max_bytes while writing (decoded > limit).")
                            tmp.write(decoded)
                            total_written += len(decoded)

                    # Flush any remainder
                    tail = decomp.flush()
                    if tail:
                        if max_bytes is not None and total_written + len(tail) > max_bytes:
                            raise ValueError("Exceeded max_bytes on decoder flush.")
                        tmp.write(tail)
                        total_written += len(tail)

                else:
                    # identity: write as-is
                    while True:
                        chunk = resp.read(_CHUNK_SIZE)
                        if not chunk:
                            break
                        if max_bytes is not None and total_written + len(chunk) > max_bytes:
                            raise ValueError("Exceeded max_bytes while writing.")
                        tmp.write(chunk)
                        total_written += len(chunk)

            os.replace(tmp_output, final_path)
            tmp_output = None  # consumed

            if file_mode is not None:
                try:
                    os.chmod(final_path, file_mode)
                except OSError as e:
                    # Non-fatal; surface as warning on stderr
                    print(f"Warning: could not chmod {oct(file_mode)} on {final_path}: {e}", file=sys.stderr)

            return True

    except error.HTTPError as e:
        print(f"HTTP error: {e.code} {e.reason} for {url}", file=sys.stderr)
    except error.URLError as e:
        print(f"URL error: {e.reason} for {url}", file=sys.stderr)
    except ssl.SSLError as e:
        print(f"TLS error: {e}", file=sys.stderr)
    except (OSError, zlib.error, ValueError) as e:
        print(f"Download error: {e}", file=sys.stderr)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
    finally:
        if tmp_output and os.path.exists(tmp_output):
            try:
                os.remove(tmp_output)
            except OSError:
                pass
        if tmp_ca_file and os.path.exists(tmp_ca_file):
            try:
                os.remove(tmp_ca_file)
            except OSError:
                pass

    return False


# ---------- CLI ----------

def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Download a file over HTTP/HTTPS with TLS controls and guardrails.")
    p.add_argument("--url", required=True, help="HTTP(S) URL to download.")
    p.add_argument("--dest", required=True, help="Destination file path or directory (if a directory, filename is inferred).")
    p.add_argument(
        "--no-verify",
        dest="verify",
        action="store_false",
        help="Disable TLS verification (HTTPS only). Default is to verify.",
    )
    p.set_defaults(verify=True)
    p.add_argument(
        "--ca-cert",
        default=None,
        help="Path to a PEM file OR a PEM string for the CA/self-signed certificate. Used only if verification is on.",
    )
    p.add_argument("--timeout", type=int, default=60, help="Network timeout in seconds (default: 60).")
    p.add_argument(
        "--max-bytes",
        type=str,
        default=None,
        help="Maximum bytes to write (e.g., '1048576', '10m', '1g'). If exceeded, the download fails.",
    )
    p.add_argument(
        "--mode",
        type=str,
        default="0644",
        help="Final file mode in octal (e.g., 0644, 0600). Use 'none' to skip chmod. Default: 0644.",
    )
    p.add_argument(
        "--user-agent",
        type=str,
        default=_DEFAULT_UA,
        help=f"User-Agent header to send. Default: {_DEFAULT_UA}",
    )
    return p


def _normalize_mode_arg(mode_arg: str) -> Optional[int]:
    if mode_arg.strip().lower() == "none":
        return None
    return _parse_mode(mode_arg)


if __name__ == "__main__":
    args = _build_arg_parser().parse_args()
    max_bytes_val = _parse_size_to_bytes(args.max_bytes) if args.max_bytes else None
    file_mode_val = _normalize_mode_arg(args.mode)

    ok = download_file(
        url=args.url,
        dest_path=args.dest,
        verify_tls=args.verify,
        ca_cert=args.ca_cert,
        timeout=args.timeout,
        max_bytes=max_bytes_val,
        user_agent=args.user_agent,
        file_mode=file_mode_val,
    )
    print("true" if ok else "false")
    sys.exit(0 if ok else 1)
