# Status
_Last updated: 2026-10-25, migrated the frontend to Tailwind 4_

## Current state
The frontend dependency tree resolves, builds and tests clean, and `npm audit`
reports nothing. Earlier today none of that was true: `npm install` failed with
`ERESOLVE` because four majors had landed without their companion packages, so
a fresh clone could not be built at all. React is now 19 throughout,
`eslint-config-next` matches Next 16, and the outstanding major bumps
(`@testing-library/jest-dom` 7, `lucide-react` 1.x, `recharts` 3) are in.

Tailwind is on 4.3.3. `globals.css` moved from `@tailwind` directives to
`@import "tailwindcss"` with `@config` pointing at the existing
`tailwind.config.js`, and the `@layer components` / `@layer utilities` classes
became `@utility` definitions, which is what lets `card-hover` and
`select-field` keep applying `card` and `input-field`.

## Recent decisions
- Finished the React 19 upgrade rather than reverting `react-dom` to 18, since
  Next 16 requires React 19 regardless.
- Migrated to Tailwind 4 rather than holding at 3.x. Holding required an
  `overrides` pin on `postcss-selector-parser`, because Tailwind 3 pulls it in
  at 6.1.x through postcss-nested and the fix for its advisory only exists in
  7.x. v4 drops that dependency chain, so the override and `autoprefixer` are
  both gone.
- Restored `cursor: pointer` on buttons in `@layer base`. Tailwind 3's preflight
  set it, v4 does not, and this app has 44 buttons written expecting it. No
  build would have caught that.
- Regenerated `package-lock.json` rather than editing it; npm's resolver
  crashed trying to update the old one in place.

## Known issues
- Tailwind 4 moved its palette to OKLCH, shifting `amber-500` from
  rgb(245,158,11) to about rgb(254,154,0). Greys moved by at most 3. But
  `#f59e0b` is still hardcoded three times in `src/app/dashboard/page.tsx` for
  the chart gradient and stroke, so the chart line no longer quite matches the
  146 `amber-*` classes around it.
- Only the signed-out page was verified in a browser; the rest of the UI is
  behind auth. Everything else was checked by comparing computed styles before
  and after, and by grep for the renamed utilities.
- `npm install` needs npm 11. npm 10.9.4 crashes resolving vitest's optional
  peer graph, which is an npm defect rather than anything in this tree.

## Open threads
- Whether to update the three hardcoded `#f59e0b` literals to match the new
  amber, which needs someone looking at the dashboard.
