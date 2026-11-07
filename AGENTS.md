# AGENTS.md

Guidance for cloud coding and review agents (Codex, Grok in Cursor, Claude) in **bloclabs-ssi-login**: a WordPress plugin that logs users in with Verifiable Credentials (OpenID4VP). A verifier attests each decision on chain through Hyperledger FireFly, and WordPress consumes the event. Start with `README.md`, `docs/ARCHITECTURE.md` and `docs/SECURITY-MODEL.md`.

**This repository is public.** Never commit a secret, a hostname or an IP address of blocLabs infrastructure.

## Who does what

This section is the only place that defines roles in this repository; the claude.ai project instructions just point here. Britney edits it when the founder changes a role.

Roles since 2026-11-04 (founder): Britney tests and deploys; Fable, Codex and Grok code and review.

- **Britney** (`bloclabs-britney`) assigns work through issues that name the coder (`Coder: <Name>`), answers design questions as code owner, tests (unit, WordPress integration and bridge tests, and end to end against the local chain and walt.id), merges pull requests that pass testing, releases, and deploys with the founder's go. She doesn't write feature code or fixes.
- **Coders:** Fable (works as `bloclabs-io`), Codex and Grok (in Cursor). Each works only on an issue that names it as coder. One coder per issue, and one pull request per issue unless the issue says otherwise.
- **Reviewers:** Codex reviews every pull request once, automatically, when it opens or is marked ready, with its security review. Fable, Codex and Grok also review each other's pull requests when the founder or Britney asks. The author fixes P0 and P1 findings on the same branch; comment `@codex review` to re-check a fix.
- **claude[bot]** reviews only when the pull request gets the `claude-review` label.
- Agents other than Britney never merge, tag, release, deploy, or touch a server, a secret or production data. The founder approves releases and anything public.

## Pull requests

- Follow `CONTRIBUTING.md`. Close one issue (`Closes #N`); no feature, refactor or dependency the issue doesn't ask for.
- Add a `CHANGELOG.md` entry under the current unreleased section at the top (now `## 0.4.0-dev (unreleased)`); don't start a second one.
- Say what you ran and what you couldn't verify.
- When the newest Codex review has no unresolved P0 or P1, post a comment on the pull request with `Handoff: test` on a line of its own. A `Handoff:` line in the description doesn't count.

## blocLabs look and feel

The plugin is generic: on any site its UI follows that site's theme, and its defaults stay WordPress's own (see the `--bloclabs-ssi-button-*` custom properties in `assets/css/login.css`). Anything blocLabs-branded (the demo in `demo/`, screenshots, docs images, the blocLabs site's own overrides) uses the blocLabs theme, measured on bloclabs.io on 2026-11-06:

| Token | Value |
|---|---|
| Primary (accent) | `#ff782d` (rgb 255,120,45) |
| Emphasis / price | `#f24c0a` |
| Body text | `#666`; headings and strong text `#333` |
| Light background | `#f7f7fa`; page background `#fff` |
| Borders | `#e8e8e8` |
| Fonts | Barlow (body, inputs), Exo (headings, labels, buttons) |
| Shapes | pill buttons (60px radius), cards and fields with 20px / 12px corners |

Official logos (founder, 2026-11-06), in [`docs/brand/`](docs/brand/): `blocLabs-original-enhanced-transparent.png` (orange wordmark, 2169x725) and `blocLabs-enhanced-white-transparent.png` (white wordmark, for dark or orange backgrounds); `blocLabs-icon-orange-transparent.png` and `blocLabs-icon-white-transparent.png` (square cube icon, 106x93) for small slots such as wallet issuer logos and favicons. Use these files only; never redraw or recolour the logo.

Contrast: white text on `#ff782d` is about 2.6:1 and fails WCAG AA, so orange buttons carry dark text (`#333` is about 4.8:1, `#000` about 8:1) or use orange as an accent only. Orange text on white also fails for body-size text.

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
