# Status
_Last updated: 2026-10-25, took the outstanding frontend major bumps and cleared the postcss advisories_

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

The three outstanding major bumps are now in: `@testing-library/jest-dom` 7,
`lucide-react` 1.x and `recharts` 3. recharts 3 changed its Tooltip formatter
signatures, so four call sites in `src/app/dashboard/page.tsx` were updated to
take the wider types and coerce inside.

`npm test` passes (8 tests, 2 files), `next build` completes with all routes
generated, and `npm audit` reports no vulnerabilities.

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
- Pinned `postcss-selector-parser` to ^7.1.7 through `overrides`. Tailwind 3
  pulls it in at 6.1.x via postcss-nested, and 6.1.5 is the newest 6.1.x, so
  there is no patched version inside the range postcss-nested asks for. The
  generated CSS is byte-identical with and without the override, which is how
  the forced major was checked.

## Known issues
- The Tailwind 4 migration is still outstanding and is the reason the pinned
  version is a major behind the latest.
- The Tailwind 4 migration is the only dependency work left. `globals.css` has
  3 `@layer` blocks, 13 custom classes and 10 `@apply` uses, one of which
  applies a custom class that v4 cannot resolve; those become `@utility`
  definitions. v4 also changes base styles, so the result needs looking at.
- `npm install` needs npm 11. npm 10.9.4 crashes resolving vitest's optional
  peer graph, which is an npm defect rather than anything in this tree.

## Open threads
- Whether to do the Tailwind 4 migration or hold at 3.x. Holding keeps the
  `postcss-selector-parser` override necessary; migrating removes the need for
  it.
