# AGENTS.md

Guidance for cloud coding and review agents (Codex, Grok in Cursor, Claude) in **bloclabs-ssi-login**: a WordPress plugin that logs users in with Verifiable Credentials (OpenID4VP). A verifier attests each decision on chain through Hyperledger FireFly, and WordPress consumes the event. Start with `README.md`, `docs/ARCHITECTURE.md` and `docs/SECURITY-MODEL.md`.

**This repository is public.** Never commit a secret, a hostname or an IP address of blocLabs infrastructure.

## Who does what

This section is the only place that defines roles in this repository; the claude.ai project instructions just point here. Britney edits it when the founder changes a role.

- **Fable** (works as `bloclabs-io`) writes the code here, because the plugin and its bridge are new and security-heavy: one branch and one pull request per issue.
- **Another coder** (Britney, Codex, or Grok in Cursor) works only on an issue that Britney or the founder assigns to it, and the issue says so. One coder per issue.
- **Codex reviews** every pull request once, automatically, when it opens or is marked ready, with its security review. The author fixes P0 and P1 findings on the same branch; comment `@codex review` to re-check a fix.
- **claude[bot]** reviews only when the pull request gets the `claude-review` label.
- **Britney** (`bloclabs-britney`) tests, merges and deploys. The founder approves releases and anything public.
- Agents other than Britney never merge, tag, release, deploy, or touch a server, a secret or production data.

## Pull requests

- Follow `CONTRIBUTING.md`. Close one issue (`Closes #N`); no feature, refactor or dependency the issue doesn't ask for.
- Add a `CHANGELOG.md` entry under the current unreleased section at the top (now `## 0.1.0-dev (unreleased)`); don't start a second one.
- Say what you ran and what you couldn't verify.
- When the newest Codex review has no unresolved P0 or P1, post a comment on the pull request with `Handoff: test` on a line of its own. A `Handoff:` line in the description doesn't count.

## Tests

```bash
composer install
composer test     # PHPUnit, no database
composer phpcs    # WordPress coding standards
composer lint     # php -l on every file
composer test:integration   # WordPress integration suite on PHPUnit 9 (bin/run-integration.sh; WP_VERSION, default 6.6.10)
```

## Code Review Rules

Flag only problems a reviewer can point to on a line. Every mitigation in `docs/SECURITY-MODEL.md` must survive the change. Don't comment on style; phpcs enforces it.

### Impersonation

- Flag any way to log in as someone else, or to complete, poll, forge or replay another browser's login attempt. Attempts are bound to the browser that started them; a missing or wrong binding must fail.
- Flag an attempt state change that is not compare-and-set, and races between the webhook, polling and completion. An attempt must be consumed exactly once.
- Flag a login path that skips WordPress's `authenticate` / `wp_authenticate_user` filters or the auth cookie defaults. Lockout and ban plugins rely on them.

### Privacy and public repository

- Flag personal data on chain or in logs, and any secret, hostname or IP address committed here.

### WordPress correctness

- Flag REST routes without a real `permission_callback`, missing nonces or capability checks, unescaped output, SQL not built with `$wpdb->prepare()`, and redirects not validated with `wp_validate_redirect()`.
- Flag a security-relevant change without a test.
