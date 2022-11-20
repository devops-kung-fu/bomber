![](../../img/providers/osv.png)

[OSV](https://osv.dev) is the default provider for ```bomber```. It is an open, precise, and distributed approach to producing and consuming vulnerability information for open source. 

**You don't need to register for any service, get a password, or a token.** Just use ```bomber``` without a provider flag and away you go like this:

``` bash
bomber scan test.cyclonedx.json
```

## Supported ecosystems

At this time, the [OSV](https://osv.dev) supports the following ecosystems:

- Android
- crates.io
- Debian
- Go
- Maven
- NPM
- NuGet
- Packagist
- PyPI
- RubyGems

and others...

## OSV Notes

The OSV provider is pretty slow right now when processing large SBOMs. At the time of this writing, their batch endpoint is not functioning, so ```bomber ``` needs to call their API one package at a time. 

Additionally, there are cases where OSV does not return a Severity, or a CVE/CWE. In these rare cases, ```bomber``` will output "UNSPECIFIED", and "UNDEFINED" respectively.



