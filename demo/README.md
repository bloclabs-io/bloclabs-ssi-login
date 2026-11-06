# Demo stack

What `./setup.sh` starts, and why it is shaped this way. The walkthrough is [Try it](../README.md#try-it) in the repository README.

`docker compose up` brings the containers up. `./setup.sh` does that and then compiles the attestor and the trusted-issuer registry, deploys them through FireFly, trusts the generated issuer, installs WordPress and prints a credential offer. Run it from this directory. On Windows, use Git Bash: the script sets `MSYS_NO_PATHCONV` so Git Bash does not rewrite the container paths, and every generated secret is read back with carriage returns stripped.

## What is published

Three ports, all on `127.0.0.1`. The defaults live in [`.env`](.env). Change a number there when another stack already uses it, then run `./setup.sh` again. Compose reads that file, and `./setup.sh` prints the addresses it actually bound. The wallet page's `WALLET_API2_PUBLIC_URL` is `http://127.0.0.1:` plus `WALLET_API_PORT`, and the wallet API's `publicBaseUrl` is the same address, rewritten on every start. The containers still listen on their own ports (WordPress 80, wallet API 7006, wallet web 8080).

| Variable | Default | Service |
|---|---|---|
| `WORDPRESS_PORT` | 8080 | WordPress |
| `WALLET_WEB_PORT` | 7106 | Web wallet |
| `WALLET_API_PORT` | 7006 | Wallet API (the page in the browser calls this) |

Everything else is on the Compose network `bloclabs-ssi-demo` and has no host port. FireFly's API has no authentication, so publishing it would expose contract deployment and the signing key's use to any local process. The issuer and the verifier are reached by name (`issuer.demo`, `verifier.demo`) through the `edge` proxy, which is also unpublished. The wallet backend resolves those names; the browser does not. That is what makes the request URL inside a presentation carry a host the wallet can open, without putting the verifier on the host.

## Keys

`keys` runs once. If `runtime/ready` is missing it generates the issuer key, the chain keys and the passwords, then exits. A later start leaves them in place, so the chain and the wallet keep the same keys. `runtime/`, `signer/` and `registry-owner/` are gitignored. Do not commit them.

Three secp256k1 keys are involved. The node key signs Besu blocks and is the validator in the genesis `extraData`. The bridge's signing key is funded, is FireFly's default key, and is the attestor's first verifier, so it can call `attest`. A different funded key owns the trusted-issuer registry. That keystore is written to `registry-owner/`. FireFly's signer never loads it: on every start it builds a tmpfs wallet from the attestor key alone, and `./setup.sh` deletes an owner keystore left in `signer/` before the containers start. Registry deployment and `setIssuer` are signed by a separate signer, `owner-signer`, attached only to the `setup` network. Besu and the one-shot deploy container are on that network. The bridge is not, so it cannot ask that signer to change the trust list, including while setup is running. The issuer key is P-256. Its `did:jwk` is written into the issuer config, into the bridge's allowed-issuer policy, and into `setIssuer` for the member credential type, so those three name the same issuer.

Postgres, MariaDB, WordPress and the bridge read those files through a small entrypoint that strips a carriage return before exporting them. The issuer and the wallet images have no shell, so their committed config is an HOCON `include` of a file under `/runtime`.

## Chain

WordPress is `wordpress:6.7.2-php8.2-apache`. Docker Hub does not publish a 6.6.10 image; 6.7.2 is a pinned release above the plugin's 6.6 requirement. The wallet and the issuer are walt.id 1.2.0, FireFly is v1.5.0 and evmconnect is v1.5.1.

Besu 24.12.2, QBFT, chain id 1337, two-second blocks. The genesis stops at Paris (`mergeNetsplitBlock`, no Shanghai timestamp) and sets `zeroBaseFee`, because both contracts are compiled with solc 0.8.28 `--evm-version paris` (a later EVM emits `PUSH0`, which this chain rejects) and evmconnect is configured with a gas price of 0. `./setup.sh` compiles with `ethereum/solc:0.8.28` and deploys through FireFly's `/contracts/deploy`. It registers the `ssi-login-attestor` API and a `LoginAttested` listener, then deploys `TrustedIssuerRegistry`, publishes `trusted-issuer-registry`, and calls `setIssuer` for the generated `did:jwk` and `http://issuer.demo/openid4vci/member`. The bridge's `FIREFLY_REGISTRY_API` is that API name, and its `FIREFLY_SIGNING_KEY` is the attestor key, not the registry owner. `isTrusted` runs before a login is attested. The registry contract and `setIssuer` are submitted through `owner-signer`, then the FireFly API is registered at the deployed address. If that API is already published, setup keeps its address and does not deploy a second contract. A later run still refreshes the credential offer and repeats `setIssuer` through `owner-signer`.

## WordPress

The official image does not install the site by itself. The `wpcli` service (Compose profile `setup`) runs `wp core install` when the site is not installed, pins `BLOCLABS_SSI_*` in `wp-config.php`, activates the plugin and runs `wp bloclabs-ssi subscribe`. Linking is `auto_provision`, so a new wallet subject becomes a subscriber. The display name is the credential's `name` claim. The credential offer is a fixed demo person, Ada Lovelace.

The repository is mounted as the plugin. Apache is told to refuse `demo/` and `.git` under that mount, and `demo/runtime`, `demo/signer` and `demo/registry-owner` are masked with empty directories, so a request to the plugin URL cannot read the generated keys.

The must-use plugin in `wordpress/mu-plugins` is the blocLabs look (Barlow, Exo, pill buttons, `#ff782d`). It is not part of the plugin. Orange text on white fails contrast for body text, and white text on `#ff782d` does too, so the orange controls use dark text.

## Reset

From this directory:

```bash
docker compose down -v
rm -rf runtime signer registry-owner
```

All of these are required. A new `runtime/` with an old chain volume (or the reverse) makes the node key and the genesis disagree, and the registry owner has to stay the key that deployed the registry.
