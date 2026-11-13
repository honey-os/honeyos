# Status
_Last updated: 2026-11-13, moved the whole repo to current versions: Node 26, exact pins, CI on pull requests_

## Current state
The repo is on current versions throughout, not only in `package.json`:

- **Node 26** (Active LTS) in every Dockerfile stage, `.nvmrc`, CI and
  `engines`. It was on Node 20, which reached end of life in April 2026.
- **Every frontend dependency is pinned exactly**, with no carets. Dependabot
  moves the pins, so each change of version is a pull request.
- **Python 3.13** for the backend. The published image takes its Python from
  the Debian release under `node:26-slim`, which is Debian 13 and ships 3.13,
  so `backend/Dockerfile` and CI were set to match it. The backend's 464 tests
  pass on 3.13 with every requirement at its latest release.
- **CI runs on every pull request** (`.github/workflows/ci.yml`): lint,
  `tsc --noEmit`, frontend tests, a frontend build, backend tests, and a build
  of the Docker image without pushing it. The image workflow calls the same
  test job, so the checks are defined once.
- **Linting works for the first time.** `next lint` was removed in Next 16 and
  no ESLint config had ever existed. There is now `frontend/eslint.config.mjs`
  and `npm run lint` runs `eslint`.

Checked locally on Node 26.13.1 from a clean `npm ci`: lint (0 errors),
`tsc --noEmit`, 8 frontend tests, `next build`, `npm audit` (0 findings), and
the built app answering on `/`, `/dashboard`, `/events` and `/settings`.

## Recent decisions
- TypeScript is held at 6.0.3, the newest release that passes. 7.0.2 fails at
  the lint step with `typescript-eslint does not support TS 7.0.`, exit 2.
  Revisit when typescript-eslint supports TS 7.
- ESLint 10.14.0 is in use although `eslint-plugin-import`, `-jsx-a11y` and
  `-react` still declare a peer range that ends at 9. It installs and lints
  clean; the declarations are out of date rather than a real limit.
- Two React Compiler lint rules (`react-hooks/set-state-in-effect` and
  `react-hooks/immutability`) are set to warn, not error. They flag seven
  existing effects, and rewriting effect logic inside a dependency upgrade,
  with no browser check, would have been the riskier choice.
- Python 3.13 rather than the newest 3.15, so that CI and the backend
  Dockerfile test the same Python the published image runs.
- `overrides` pins `minimatch` 10.x to 11.0.8 for the lint toolchain, which
  asks for `^10` while the fixed releases are 11.x. Remove it when eslint and
  typescript-eslint ask for 11 themselves. The old `js-yaml` override is gone:
  nothing in the tree depends on it any more.
- Dependabot now also covers GitHub Actions and the Docker base images.
- Earlier, still current: Tailwind 4 with `@config` pointing at the existing
  `tailwind.config.js`, and `cursor: pointer` restored on buttons.

## Known issues
- The Docker images were not built locally (no Docker daemon on the machine
  that did this work). The `image-build` job on the pull request is what
  proves the Node 26 and Debian 13 bases build.
- Lint reports 15 warnings: the seven effects above, one missing effect
  dependency in `src/app/events/page.tsx`, and seven unused imports or
  variables.
- Only two frontend test files exist, so "the tests pass" says little about
  the UI. No page was looked at in a browser after this upgrade; the built app
  was only checked for answering requests.
- `Query.get()` is used in backend tests and is deprecated in SQLAlchemy 2.
- Tailwind 4 moved its palette to OKLCH, shifting `amber-500`. `#f59e0b` is
  still hardcoded three times in `src/app/dashboard/page.tsx` for the chart,
  so the chart line no longer quite matches the `amber-*` classes around it.

## Open threads
- Whether to make `build-and-test` a required status check on `main`. CI
  reports today but does not block a merge.
- Rewriting the seven flagged effects, then turning the two rules back to
  errors. Needs someone looking at the session player and the detail pages.
- Whether to update the three hardcoded `#f59e0b` literals to the new amber.
