![](../../img/providers/github.png)

# GitHub Advisory Database

In order to use `bomber` with the [Github Advisory Database](https://github.com/advisories) you need to have a GitHub account.

Once you log in, you'll want to navigate to your [settings](https://github.com/settings/tokens) and and create a Personal Access Token (PAT). **Please don't share your token with anyone.**

Once you have your token, you can either set an environment variable called `GITHUB_TOKEN` or utilize the token on the command line as such:

```bash
# Using a provider that requires credentials (ossindex)
bomber scan --provider=github --token=xxx sbom.json
```

## Supported ecosystems

At this time, the [Github Advisory Database](https://github.com/advisories) supports the following ecosystems:

- GitHub Actions
- Composer
- Erlang
- Go
- Maven
- npm
- NuGet
- Pip
- PyPI
- RubyGems
- Rust
