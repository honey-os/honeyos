# Status
_Last updated: 2026-10-25, aligned the frontend dependency tree so it installs and builds again_

## Current state
The frontend dependency tree resolves and builds. Before this, `npm install` in
`frontend/` failed outright with `ERESOLVE`, and the build failed after that on
a PostCSS plugin error, so a fresh clone could not be built at all.

Four version pairs were out of step, each from a major bump that landed without
its companion package:

- `react` 18 under `react-dom` 19, and `@types/react` 18 under
  `@types/react-dom` 19. React is now 19 throughout, which is what `react-dom`
  19 and Next 16 both require.
- `eslint-config-next` 14 under `eslint` 10 and Next 16. Now 16.x, whose
  peer range accepts eslint 10.
- `tailwindcss` 4 with a Tailwind 3 PostCSS setup. Reverted to 3.4.19.
- `vitest` 4.1.11, which pinned a transitive package to a version with a
  published advisory. Now 4.1.12, and `npm audit` reports clean.

`npm test` passes (8 tests, 2 files) and `next build` completes with all routes
generated.

## Recent decisions
- Reverted Tailwind to 3.4.19 rather than migrating to 4. The 4.x bump was not
  deliberate: dependabot is configured to keep majors out of grouped PRs, and
  this one arrived paired with a postcss update. A real v4 migration means
  porting `tailwind.config.js` to CSS-first config and would change rendered
  output, which is a separate, deliberate piece of work.
- Finished the React 19 upgrade instead of reverting `react-dom` to 18, because
  Next 16 requires React 19 regardless.
- Regenerated `package-lock.json` from scratch. The old one could not be
  updated in place; npm's resolver crashed on it.

## Known issues
- The Tailwind 4 migration is still outstanding and is the reason the pinned
  version is a major behind the latest.
- Three major dependency bumps are open and want review rather than a blind
  merge: lucide-react 0.x to 1.x renames icon exports, recharts 2 to 3 reworked
  the chart APIs, and @testing-library/jest-dom 6 to 7 drops matchers.
- `npm install` needs npm 11. npm 10.9.4 crashes resolving vitest's optional
  peer graph, which is an npm defect rather than anything in this tree.

## Open threads
- Whether to do the Tailwind 4 migration or hold at 3.x.
- The three major bumps above, one at a time.
