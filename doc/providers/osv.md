![](../../img/providers/osv.png)

[OSV](https://osv.dev) is the default provider for ```bomber```. It is an open, precise, and distributed approach to producing and consuming vulnerability information for open source. 

**You don't need to register for any service, get a password, or a token.** Just use ```bomber``` without a provider flag and away you go like this:

``` bash
bomber scan test.cyclonedx.json
```

## Supported ecosystems

At this time, the [OSV](https://osv.dev) supports the following ecosystems:

- Alpine Linux
- Bitnami
- Cargo (Rust)
- ConanCenter
- Debian Linux
- GitHub Actions
- Go
- Gradle
- Hex (Erlang/Elixir)
- Linux Kernel
- Maven
- npm
- NuGet
- OSS-Fuzz
- Packagist (PHP)
- PyPI
- RubyGems
- SwiftURL
- and others...

## OSV Notes

Additionally, there are cases where OSV does not return a Severity, or a CVE/CWE. In these rare cases, ```bomber``` will output "UNSPECIFIED", and "UNDEFINED" respectively.



