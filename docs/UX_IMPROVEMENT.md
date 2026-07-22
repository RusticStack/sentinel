# Sentinel — UX Improvement Plan

Late-phase guidance for polish, onboarding, and help — after core auth, data, UI, islands, Vigil, and deploy (see Phase 7 in `TODO.md`).

**Product shape (locked):** auth-first. Unauthenticated visitors see a locked login gate; the dashboard chrome appears only after sign-in. Design language stays Apple translucent + Fresh lemon (light summer glass) — not a dark ops console.

**Stack constraints:** Fresh 2.3 + Preact. Prefer server-rendered HTML; put interactive UX only in `islands/`. Vanilla JS libraries (e.g. Driver.js) are fine inside islands.

---

## 1. Onboarding library — Driver.js (recommended)

[Driver.js](https://driverjs.com/) is a lightweight, zero-dependency vanilla JS library for product tours, spotlight highlights, and contextual popovers.

### Why Driver.js for Sentinel

| Factor | Fit |
|--------|-----|
| Fresh islands | Vanilla JS — import in an island; no React wrapper required |
| Bundle size | Small; no framework lock-in |
| Theming | `popoverClass` + CSS overrides → match glass + lemon tokens |
| Features | Multi-step tours, single-element highlight, progress, keyboard |

### Alternatives

| Option | When to consider |
|--------|------------------|
| **Shepherd.js** | Heavier; more step lifecycle hooks if tours get complex |
| **Custom** (`<dialog>` + CSS mask) | Only if we need zero third-party deps and a 1–2 step tip |

**Recommendation:** Driver.js for first-run / Help → “Tour the dashboard”. Theme popovers with Sentinel tokens (surface glass, lemon accent buttons, IBM Plex). Respect `prefers-reduced-motion` (skip or shorten animations).

### Island sketch (Phase 7)

```ts
// islands/DashboardTour.tsx — client-only
import { useEffect } from "preact/hooks";
import { driver } from "driver.js";
import "driver.js/dist/driver.css";

export default function DashboardTour({ autoStart = false }: { autoStart?: boolean }) {
  useEffect(() => {
    if (!autoStart) return;
    const d = driver({
      showProgress: true,
      popoverClass: "sentinel-driver",
      steps: [
        { element: "[data-tour='nav']", popover: { title: "Navigation", description: "…" } },
        { element: "[data-tour='runners']", popover: { title: "Runners", description: "…" } },
        // …
      ],
    });
    d.drive();
    return () => d.destroy();
  }, [autoStart]);
  return null;
}
```

Add `data-tour` hooks on server-rendered shell panels so the tour targets stable selectors.

---

## 2. Form improvements checklist

- [ ] Visible labels on every input (no placeholder-only labels)
- [ ] Inline validation messages tied with `aria-describedby` / `aria-invalid`
- [ ] Consistent error summary at top of multi-field forms when needed
- [ ] Disable submit while in-flight; show clear pending state
- [ ] Prefer native controls (`<input>`, `<select>`, `<dialog>`) before custom widgets
- [ ] Focus first error field on failed submit
- [ ] Auth / settings forms match glass panel language (not a separate “form theme”)

*Note: Phase 1 login is mostly a single OAuth CTA; richer forms appear later (filters, Vigil-related UI).*

---

## 3. Navigation & layout checklist

- [ ] Auth-first: unauthenticated → `/auth/login`; authenticated → dashboard `/` (no unlocked dashboard peek)
- [ ] Primary nav only after auth (Dashboard / Runners / Runs / Security if Vigil / Help / Logout)
- [ ] Current route via `aria-current="page"`; disabled placeholders never look clickable as real links
- [ ] Skip link to `#main` retained in `_app.tsx`
- [ ] Mobile: collapse secondary nav; stack metric panels; no horizontal overflow traps
- [ ] Sticky glass header stays thin; content has one clear hierarchy per page
- [ ] Empty / loading / error regions share layout slots so the shell does not jump

---

## 4. Visual & accessibility checklist

- [ ] Contrast: body text and muted text meet WCAG AA on glass surfaces
- [ ] Status chips: color **and** label (`StatusBadge`) — never color alone
- [ ] Focus rings visible on interactive controls (accent-aware, not browser-default only)
- [ ] Hit targets ≥ 44×44px where practical on touch
- [ ] `prefers-reduced-motion`: disable non-essential fades / tour motion
- [ ] Icons decorative → `aria-hidden`; meaningful icons need accessible names
- [ ] Dark mode: **optional / later** — current design is light summer glass; do not block Phase 7 on a dark theme
- [ ] No Live/Offline connection theater badges in the shell

---

## 5. Content & language checklist

- [ ] Short, operational copy (“Sign in to continue”, not marketing hero slogans)
- [ ] Error messages say what failed and what to do next (org membership denied, API down)
- [ ] Empty states explain *why* empty and the next action
- [ ] Consistent terms: runner, workflow run, org, finding (Vigil)
- [ ] Avoid emoji as UI chrome; keep mono for IDs / metrics / timestamps

---

## 6. Help & guidance system checklist

- [ ] **Help** item in authenticated nav (page or panel)
- [ ] First-run optional Driver.js tour (dismissible; don’t re-show after dismiss without “Replay tour”)
- [ ] Persist “tour seen” in `localStorage` (or session) — client-only is fine for v1
- [ ] Contextual tips near dense panels (runners grid, Vigil findings) via highlight or short copy
- [ ] Link out to `README` / ops docs for deploy and env setup where relevant
- [ ] Keyboard: Esc closes tour / dialogs; focus returns to trigger

---

## 7. Interaction & feedback checklist

- [ ] Optimistic quiet refresh for WS/poll updates (no flashy “live” chrome)
- [ ] Toast or inline banner for user-initiated actions (logout, filter apply) — soft glass, not alert spam
- [ ] Destructive actions confirm via `<dialog>`
- [ ] Loading: skeleton / placeholder bars already in design language; reuse them
- [ ] Failed fetch: retry affordance on the panel that failed
- [ ] Buttons: primary = lemon accent; secondary = glass border — one primary per view when possible

---

## 8. Phased implementation

### Foundation (with or just after core UI)

1. Solidify auth-first routing and empty/error/loading patterns
2. A11y pass on shell, tables, and status chips
3. Form label / focus / error conventions documented by example components

### Guidance (Driver.js)

1. Add `driver.js` dependency; theme CSS under Sentinel tokens (`sentinel-driver`)
2. Island: `DashboardTour` (+ optional “Replay” control on Help)
3. `data-tour` attributes on nav and key dashboard regions
4. Help nav item + short help page (how auth works, what runners mean, Vigil optional)

### Polish

1. Motion refinement under `prefers-reduced-motion`
2. Mobile nav / stack polish
3. Content pass on empty and error strings
4. Optional: Shepherd only if Driver.js proves insufficient
5. Dark mode — still optional / later

---

## Compatibility notes

| Topic | Guidance |
|-------|----------|
| Fresh islands | Driver.js runs only in islands (`useEffect` / client); SSR pages stay free of tour JS |
| Preact | Use Preact hooks in islands; don’t pull React-only tour wrappers |
| Design | Style Driver popovers to glass + lemon; avoid default Driver dark overlay look if it clashes |
| Auth-first | Tours target **authenticated** dashboard only — never the locked login gate |

---

## References

- Driver.js docs: https://driverjs.com/
- Fresh islands: https://usefresh.dev/docs/concepts/islands
- Project design tokens: `assets/styles.css`, design direction in `TODO.md`
- Auth flow: `AGENTS.md`, `plan.md`
