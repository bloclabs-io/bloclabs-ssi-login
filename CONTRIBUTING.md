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
6. **wp-env runs the integration suite** without a local PHP or MySQL install. It needs Docker and Node.js 22.13 or newer:

   ```bash
   npm install
   npm run test:wp-env
   ```

   That starts the WordPress 6.6.10 environment in `.wp-env.json` and runs `tests/Integration` inside it, once as a single site and once with `WP_MULTISITE=1`. It is the same suite as `composer test:integration`. Pull requests run it as the Integration (wp-env) job. The MySQL integration jobs are separate and unchanged.

By contributing you agree that your work is licensed under GPL-2.0-or-later.
