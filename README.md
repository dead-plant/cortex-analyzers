# cortex-analyzers
Collection of multiple cortex analyzers

# Deployment
See the original [documentation](https://thehive-project.github.io/Cortex-Analyzers/dev_guides/dockerize-your-custom-analyzers-responders/) for additional guideline.

# UrlListCheck
Data Types: URL, Domain, FQDN

Checks if URL or Domain is present on a bad url list after creating some additional variations of the original url/domain.
The list can be any plain text list served over http(s) which has one url/domain per line.
