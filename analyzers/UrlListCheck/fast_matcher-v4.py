#!/usr/bin/env python3
"""
fast_matcher.py

Given:
- path to a newline-separated list of URLs and domains (exact-string entries)
- an input value
- a type specifier: "url" or "domain"

Outputs:
- dict(str, bool): {"hardmatch": <bool>, "softmatch": <bool>}

Rules implemented:
- Only exact line matches (no partials).
- All comparisons are performed in **lowercase**: the list entries are loaded as lowercase and every candidate is normalized to lowercase before checking.
- For URLs:
  * Consider the unmodified input and the input with http(s) stripped as "hard" candidates.
  * mod1: strip auth (user:pass@) -> hard candidate.
  * mod2: reduce to host (no port/path/etc), then:
      - mod3: strip subdomains left-to-right down to the registrable core using the Public Suffix List when available (tldextract); fallback heuristic keeps last two labels.
      - mod4: for each mod3 variant, test both with and without a trailing dot.
    Any match derived from mod2/mod3/mod4 is ALWAYS a soft match (even if the string looks like a domain "hard" by itself).
- For Domains:
  * mod3: strip subdomains left-to-right (careful: do not do this for IPs).
  * mod4: test each domain variant with and without a trailing dot.
  * Any domain match here is a HARD match.
- IP addresses:
  * Detected via ipaddress; we do not perform subdomain stripping nor trailing-dot variants for IPs.
- Performance:
  * The list is loaded once into a set for O(1) membership checks.
  * Lines are stripped of surrounding whitespace; empty lines are ignored.
- Robustness:
  * Handles IPv6 (including bracketed form in URLs).
  * Parsing URLs even when the scheme is missing (we temporarily add http:// just to parse).
  * Optional support for gzip/bz2/xz via file extension.
  * IDN handling: Unicode domains are normalized to punycode for matching; candidates are expanded to both punycode (xn--) and Unicode forms.

NOTE: Registrable-domain detection uses the Public Suffix List via `tldextract` when available; otherwise the matcher falls back to a simple heuristic (keep last two labels). This avoids false positives/negatives on multi-label TLDs like *.co.uk.
"""

from __future__ import annotations
import argparse
import bz2
import gzip
import io
import ipaddress
import lzma
import os
import re
from typing import Dict, Iterable, List, Set, Tuple
from urllib.parse import urlsplit

# Optional: Public Suffix List for accurate registrable domains
try:
    import tldextract  # type: ignore
    # Use packaged PSL; avoid network fetch for deterministic behavior
    _TLDEX = tldextract.TLDExtract(suffix_list_urls=None)
    _HAS_PSL = True
except Exception:
    _TLDEX = None  # type: ignore
    _HAS_PSL = False

# ----------------------- File loading -----------------------

def _open_maybe_compressed(path: str) -> io.TextIOBase:
    """Open plain/gz/bz2/xz text files as UTF-8 (BOM-safe) with universal newline handling."""
    lower = path.lower()
    if lower.endswith(".gz"):
        return io.TextIOWrapper(
            gzip.open(path, "rb"),
            encoding="utf-8-sig",
            errors="replace",
            newline=None,  # universal newlines
        )
    if lower.endswith(".bz2"):
        return io.TextIOWrapper(
            bz2.open(path, "rb"),
            encoding="utf-8-sig",
            errors="replace",
            newline=None,  # universal newlines
        )
    if lower.endswith(".xz") or lower.endswith(".lzma"):
        return io.TextIOWrapper(
            lzma.open(path, "rb"),
            encoding="utf-8-sig",
            errors="replace",
            newline=None,  # universal newlines
        )
    return open(path, "r", encoding="utf-8-sig", errors="replace", newline=None)


def load_blocklist(path: str) -> Set[str]:
    """Load the list file into a set of lines, stripped and lowercased; skip empty lines."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"List file not found: {path}")
    s: Set[str] = set()
    with _open_maybe_compressed(path) as fh:
        for line in fh:
            # Keep EXACT strings except surrounding whitespace/newlines; normalize to lowercase
            entry = line.strip().lower()
            if entry:
                s.add(entry)
    return s

# ----------------------- Helpers -----------------------

# Match http/https/hxxp/hxxps specifically, plus a generic RFC3986 scheme matcher
_HTTPISH_RE   = re.compile(r'^(?:https?|hxxps?)://', re.IGNORECASE)
_ANY_SCHEME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9+.-]*://', re.IGNORECASE)

def strip_scheme(url: str) -> str:
    """Remove a single leading scheme once: http(s)://, hxxp(s)://, or any RFC3986 scheme."""
    if _HTTPISH_RE.match(url):
        return _HTTPISH_RE.sub("", url, count=1)
    # Fallback: strip any scheme (ftp, ws, custom, etc.)
    return _ANY_SCHEME_RE.sub("", url, count=1)
def remove_auth(no_scheme_url: str) -> str:
    """
    Remove auth part from the start of a scheme-less URL if present:
    user[:pass]@host[:port]/...
    Only removes if '@' occurs before first '/'.
    """
    first_slash = no_scheme_url.find("/")
    at = no_scheme_url.find("@")
    if at != -1 and (first_slash == -1 or at < first_slash):
        return no_scheme_url[at + 1 :]
    return no_scheme_url

def parse_host_from_url(url: str) -> str | None:
    """
    Return hostname from URL (lower-cased by urllib), ignoring port.
    If url lacks scheme, temporarily prefix http:// for parsing.
    """
    u = url
    if not _ANY_SCHEME_RE.match(u):
        u = "http://" + u
    try:
        parts = urlsplit(u)
        # hostname is already de-bracketed for IPv6 and lower-cased
        return parts.hostname
    except Exception:
        return None

def is_ip_literal(host: str) -> bool:
    """ True if host is IPv4 or IPv6 literal (not bracketed). """
    if host is None:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False

def domain_labels(host: str) -> List[str]:
    """Split host into labels (assumes no trailing dot)."""
    return [lbl for lbl in host.split(".") if lbl]

def chop_subdomains(host: str) -> List[str]:
    """
    PSL-aware subdomain chopping (mod3):
    - Produce variants by stripping left-most labels down to the registrable domain (inclusive).
    - Never go below the registrable domain (e.g., never return a bare PSL like "co.uk").
    - Fallback heuristic (last two labels) if PSL data is unavailable.
    """
    labels = domain_labels(host)
    if len(labels) <= 1:
        return [host]

    # Determine how many labels the registrable domain spans
    reg_len: int | None = None
    if _HAS_PSL:
        try:
            ext = _TLDEX(host)  # type: ignore
            if ext.suffix:
                registrable = (ext.domain + "." + ext.suffix) if ext.domain else ext.suffix
                reg_len = len([l for l in registrable.split(".") if l])
            else:
                reg_len = None
        except Exception:
            reg_len = None

    if reg_len is None:
        # Fallback: keep at least last two labels
        reg_len = 2 if len(labels) >= 2 else len(labels)

    variants: List[str] = []
    # i ranges so that remaining labels count >= reg_len
    for i in range(0, len(labels) - reg_len + 1):
        remaining = labels[i:]
        variants.append(".".join(remaining))
    return variants

def with_without_trailing_dot(variants: Iterable[str], ip_ok: bool = False) -> List[str]:
    """
    mod4: return each domain variant with and without trailing dot.
    Skip the dotted form for IPs unless ip_ok=True (we default to False).
    """
    out = []
    for v in variants:
        out.append(v)
        # Add trailing dot only if it looks like a domain (not an IP)
        if not is_ip_literal(v):
            if not v.endswith("."):
                out.append(v + ".")
            else:
                # If input already had a trailing dot, include the version without it
                out.append(v[:-1])
    # Dedup while preserving order
    seen = set()
    deduped = []
    for v in out:
        if v not in seen:
            seen.add(v)
            deduped.append(v)
    return deduped

def _contains(entries: Set[str], candidate: str) -> bool:
    """Membership test against a lowercased set, normalizing candidate to lowercase once."""
    try:
        return candidate.lower() in entries
    except Exception:
        return False

# ----------------------- IDN & URL host helpers -----------------------

def _idna_encode(label: str) -> str:
    """Encode a Unicode domain to ASCII punycode using IDNA; preserve trailing dot."""
    if not label:
        return label
    trail_dot = label.endswith(".")
    core = label[:-1] if trail_dot else label
    try:
        puny = core.encode("idna").decode("ascii").lower()
    except Exception:
        puny = core.lower()
    return puny + ("." if trail_dot else "")


def _idna_decode(label: str) -> str:
    """Decode a punycode ASCII domain to Unicode if applicable; preserve trailing dot."""
    if not label:
        return label
    trail_dot = label.endswith(".")
    core = label[:-1] if trail_dot else label
    try:
        uni = core.encode("ascii").decode("idna").lower()
    except Exception:
        uni = core.lower()
    return uni + ("." if trail_dot else "")


def host_idn_variants(host: str) -> List[str]:
    """Return [lower, punycode, unicode] variants for a host (skip IPs)."""
    base = host.lower()
    if is_ip_literal(base):
        return [base]
    variants = [base, _idna_encode(base), _idna_decode(base)]
    seen = set()
    out: List[str] = []
    for v in variants:
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def _rebuild_netloc(username: str | None, password: str | None, host: str | None, port: int | None) -> str:
    if host is None:
        return ""
    net = ""
    if username is not None:
        net += username
        if password is not None:
            net += f":{password}"
        net += "@"
    # bracket IPv6 host if needed
    try:
        ipaddress.ip_address(host)
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
    except Exception:
        pass
    net += host
    if port is not None:
        net += f":{port}"
    return net


def url_host_idn_variants(url_like: str) -> List[str]:
    """
    Given a URL-like string (may be scheme-less), return variants where the host is
    lowercased, punycoded, and unicode-decoded. The original string is included.
    """
    variants = [url_like]
    parsed = urlsplit(url_like if _ANY_SCHEME_RE.match(url_like) else ("http://" + url_like))
    host = parsed.hostname
    if not host:
        return variants
    for hv in host_idn_variants(host):
        if hv == host:
            continue
        netloc = _rebuild_netloc(parsed.username, parsed.password, hv, parsed.port)
        rebuilt = parsed._replace(netloc=netloc)
        full = rebuilt.geturl()
        if not _ANY_SCHEME_RE.match(url_like):
            full = full.split("://", 1)[1]  # drop injected scheme
        if full not in variants:
            variants.append(full)
    return variants

# ----------------------- Variant generation -----------------------

def generate_url_variants(value: str) -> Tuple[List[str], List[str]]:
    """
    For an input typed as URL, return (hard_candidates, soft_candidates)

    hard:
      - original as-is
      - scheme stripped (supports http/https, hxxp/hxxps, or any RFC3986 scheme)
      - scheme stripped + auth stripped (mod1)
      - IDN-expanded variants of each hard candidate (host punycoded/unicode)

    soft:
      - domain-only host (mod2) + mod3 (PSL-aware subdomain chopping) + mod4 (trailing dot variants)
      - IDN-expanded host variants included
      (NOTE: any match derived from mod2+ is ALWAYS soft.)
    """
    original = value.strip()
    no_scheme = strip_scheme(original)

    # Hard candidates (base)
    hard_base = [original]
    if no_scheme != original:
        hard_base.append(no_scheme)
    mod1 = remove_auth(no_scheme)
    if mod1 != no_scheme:
        hard_base.append(mod1)

    # Expand hard candidates with IDN host variants
    hard: List[str] = []
    for cand in hard_base:
        hard.extend(url_host_idn_variants(cand))

    # Soft candidates via domain reduction (mod2->mod3->mod4) with IDN
    host = parse_host_from_url(original if _ANY_SCHEME_RE.match(original) else "http://" + original)
    soft: List[str] = []
    if host:
        if is_ip_literal(host):
            host_variants = [host.lower()]
        else:
            chopped = chop_subdomains(host.lower())
            idn_hosts: List[str] = []
            for h in chopped:
                idn_hosts.extend(host_idn_variants(h))
            host_variants = with_without_trailing_dot(idn_hosts)
        soft.extend(host_variants)

    def _dedupe(seq: List[str]) -> List[str]:
        seen = set()
        out = []
        for x in seq:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    return _dedupe(hard), _dedupe(soft)


def generate_domain_variants(value: str) -> List[str]:
    """
    For an input typed as DOMAIN, return hard candidates only (domains are always hard).
    Apply mod3 (PSL-aware subdomain chopping) and mod4 (with/without trailing dot).
    Include IDN (punycode and Unicode) variants for each domain candidate.
    Be careful with IPs (no chopping and no trailing dot variants).
    """
    v = value.strip().lower()
    base = v[:-1] if v.endswith(".") else v

    if is_ip_literal(base):
        return [base]

    chopped = chop_subdomains(base)
    if base not in chopped:
        chopped = [base] + chopped

    expanded: List[str] = []
    for d in chopped:
        expanded.extend(host_idn_variants(d))

    return with_without_trailing_dot(expanded)

# ----------------------- Core API -----------------------

def check_membership(list_path: str, value: str, value_type: str) -> Dict[str, bool]:
    """
    Main entry point.
    Trims surrounding whitespace on input value once.
    """
    value = value.strip()

    if value_type not in {"url", "domain"}:
        raise ValueError('value_type must be "url" or "domain"')

    # Load list to a set for O(1) membership checks
    try:
        entries = load_blocklist(list_path)
    except Exception as e:
        raise RuntimeError(f"Failed to load list from {list_path}: {e}") from e

    hard = False
    soft = False

    try:
        if value_type == "url":
            hard_candidates, soft_candidates = generate_url_variants(value)

            # Check hard candidates first (but we must continue checking all)
            for cand in hard_candidates:
                if _contains(entries, cand):
                    hard = True

            # Check soft candidates (domain-derived)
            for cand in soft_candidates:
                if _contains(entries, cand):
                    soft = True

        else:  # domain
            domain_candidates = generate_domain_variants(value)
            for cand in domain_candidates:
                if _contains(entries, cand):
                    hard = True
            # By rule, pure domain input does not produce soft matches
            soft = False

    except Exception as e:
        # Any unexpected parsing/logic error is contained; include input for easier triage
        raise RuntimeError(f"Failed to process input for value='{value}' (type={value_type}): {e}") from e

    return {"hardmatch": hard, "softmatch": soft}

# ----------------------- CLI -----------------------

def _main():
    p = argparse.ArgumentParser(description="Check URL/domain presence in a large list with specific matching rules.")
    p.add_argument("list_path", help="Path to list file (plain/gz/bz2/xz).")
    p.add_argument("value", help="Input URL or domain/host.")
    p.add_argument("type", choices=["url", "domain"], help='Specify whether "value" is a URL or a domain.')
    args = p.parse_args()

    try:
        result = check_membership(args.list_path, args.value, args.type)
        print(result)
    except Exception as e:
        # Clean, single-line error for automation/logging
        print({"error": str(e)})
        raise

if __name__ == "__main__":
    _main()
