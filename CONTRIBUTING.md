# Contributing

Thanks for helping. A few rules keep a login plugin safe to change.

1. **Open an issue first** for anything beyond a small fix, so the design can be agreed before code is written.
   Architecture decisions are recorded in [docs/adr/](docs/adr/); a change that alters one adds a new ADR.
2. **Tests and standards must pass:** `composer test` and `composer phpcs` (WordPress coding standards, PHP 8.1+).
   Security-relevant logic (status transitions, decoding, binding, commitments) needs a unit test.
3. **Never weaken a mitigation** in [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) without saying so in the pull
   request and updating that document.
4. **No personal data on chain**, ever: commitments only.
5. Write commit messages and docs in plain English; explain why, not only what.

By contributing you agree that your work is licensed under GPL-2.0-or-later.
