![](../../img/providers/sonatype.png)

# OSS Index

In order to use ```bomber``` with the [Sonatype OSS Index](https://ossindex.sonatype.org) you need to get an account. Head over to the site, and create a free account, and make note of your ```username``` (this will be the email that you registered with). 

Once you log in, you'll want to navigate to your [settings](https://ossindex.sonatype.org/user/settings) and make note of your API ```token```. **Please don't share your token with anyone.**

Once you have your token, 

``` bash
# Using a provider that requires credentials (ossindex)
bomber scan --provider=ossindex --username=xxx --token=xxx sbom.json
```

## Supported ecosystems

At this time, the [Sonatype OSS Index](https://ossindex.sonatype.org) supports the following ecosystems:

- Maven
- NPM
- Go
- PyPi
- Nuget
- RubyGems
- Cargo
- CocoaPods
- Composer
- Conan
- Conda
- CRAN
- RPM
- Swift