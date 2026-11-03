=== blocLabs SSI Login ===
Contributors: bloclabs
Tags: ssi, verifiable credentials, openid4vp, passwordless, login
Requires at least: 6.6
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 0.1.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Passwordless login with Verifiable Credentials (OpenID4VP). Every login decision is attested on chain through Hyperledger FireFly.

== Description ==

Visitors log in by presenting a credential from their identity wallet. A verifier checks it and records its decision on a blockchain through Hyperledger FireFly; FireFly notifies WordPress, which logs the visitor in. Only commitments go on chain, never personal data.

**Pre-alpha.** The verifier bridge this plugin talks to is not released yet. See the GitHub repository for status and architecture.

== Installation ==

1. Install and activate the plugin.
2. Run a verifier bridge and a FireFly node with the SsiLoginAttestor contract (see docs/FIREFLY-FLOW.md on GitHub).
3. Configure Settings → SSI Login, and put secrets in wp-config.php as BLOCLABS_SSI_* constants.
4. Run `wp bloclabs-ssi subscribe` to create the FireFly webhook subscription.

== Changelog ==

= 0.1.0 =
* First public scaffold.
