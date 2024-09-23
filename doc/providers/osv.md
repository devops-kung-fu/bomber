![](../../img/providers/osv.png)

[OSV](https://osv.dev) is the default provider for `bomber`. It is an open, precise, and distributed approach to producing and consuming vulnerability information for open source.

**You don't need to register for any service, get a password, or a token.** Just use `bomber` without a provider flag and away you go like this:

```bash
bomber scan test.cyclonedx.json
```

## Supported ecosystems

At this time, the [OSV](https://osv.dev) supports the following ecosystems:

- AlmaLinux
- Alpine
- Android
- Bitnami
- crates.io
- Curl
- Debian GNU/Linux
- Git (including C/C++)
- GitHub Actions
- Go
- Haskell
- Hex
- Linux kernel
- Maven
- npm
- NuGet
- OSS-Fuzz
- Packagist
- Pub
- PyPI
- Python
- R (CRAN and Bioconductor)
- Rocky Linux
- RubyGems
- SwiftURL
- Ubuntu OS

## OSV Notes

Additionally, there are cases where OSV does not return a Severity, or a CVE/CWE. In these rare cases, `bomber` will output "UNSPECIFIED", and "UNDEFINED" respectively.
