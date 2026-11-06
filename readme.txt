=== blocLabs SSI Login ===
Contributors: bloclabs
Tags: ssi, verifiable credentials, openid4vp, passwordless, login
Requires at least: 6.6
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 0.3.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Passwordless login with Verifiable Credentials (OpenID4VP). Every login decision is attested on chain through Hyperledger FireFly.

== Description ==

Visitors log in by presenting a credential from their identity wallet. A verifier checks it and records its decision on a blockchain through Hyperledger FireFly; FireFly notifies WordPress, which logs the visitor in. Only commitments go on chain, never personal data.

**0.3.0, first release.** The reference verifier bridge lives in the repository's bridge/ directory. Real phone-wallet logins (Paradym on iOS) have run end to end; an external security review is still to come (1.0). See the GitHub repository for status and architecture.

== Installation ==

1. Install and activate the plugin.
2. Run a verifier bridge and a FireFly node with the SsiLoginAttestor contract (see docs/FIREFLY-FLOW.md on GitHub).
3. Configure Settings → SSI Login (on multisite, as a network administrator), and put secrets in wp-config.php as BLOCLABS_SSI_* constants.
4. Run `wp bloclabs-ssi subscribe` to create the FireFly webhook subscription (add `--webhook-url=<internal address>` when FireFly reaches WordPress over a private network).

Behind a proxy, set the client IP header in Settings → SSI Login only when the site is reachable through that proxy alone, and leave it empty when the web server already resolves the client address (Apache mod_remoteip, which the official WordPress Docker image turns on, or nginx real_ip): the header PHP sees has been trimmed, and the login rate limit would count whatever a visitor writes in it. The settings page warns when the configured header is missing from your own request.

== Changelog ==

= 0.3.0 =
* First release: OpenID4VP 1.0 login with SD-JWT VC, on-chain attestation through FireFly, on-chain trusted-issuer registry, linking a credential to an existing account, signed requests, and the Digital Credentials API path.

= 0.1.0 =
* First public scaffold.
