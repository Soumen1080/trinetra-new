# UX Implementation Status (§4 Checklist)

This document tracks the implementation status of all UX requirements from §4 of the plan.

## Implementation Summary

**Status:** Partial implementation exists. Core pages built, but §4 checklist items need verification/completion.

### What Exists ✅
- ✅ React/TypeScript frontend with Vite
- ✅ Routing with react-router
- ✅ Authentication flow
- ✅ Basic pages: Dashboard, Scans, Explorer, Risk, Migration, Artefact, Glossary
- ✅ Shell component with layout
- ✅ API client integration
- ✅ Component library started

### What Needs Implementation/Verification 🔨

## §4.1: Personas and Entry Points

**Current Status:** Partially implemented (role-based auth exists)

- [ ] **4.1a** Document primary persona for each screen
  - Need to add persona documentation to each page component
  - Personas: Executive, Security Analyst, Developer
  
- [ ] **4.1b** Persona switcher or role-based landing
  - **Auth exists** but need role-based default routes
  - Executive → Dashboard with top 5 items
  - Analyst → Explorer with risk filters
  - Developer → Scans with recent scans

**Implementation:**
```typescript
// Add to Shell.tsx or create PersonaSwitcher.tsx
function getDefaultRoute(user: User): string {
  switch (user.role) {
    case 'executive': return '/dashboard';
    case 'analyst': return '/explorer';
    case 'developer': return '/scans';
    default: return '/dashboard';
  }
}
```

---

## §4.2: Progressive Disclosure

**Current Status:** Needs verification and enhancement

- [ ] **4.2a** Three-layer depth (summary → list → detail)
  - **Verify:** Each page starts at summary level
  - Dashboard → headline numbers ✅
  - Explorer → artefact list → artefact detail ✅
  - Need to check if all views follow this pattern

- [ ] **4.2b** Dashboard shows ≤5 headline numbers
  - **Verify:** Current dashboard implementation
  - Add limit if showing more than 5

- [ ] **4.2c** Advanced controls behind "Advanced" button
  - **Add:** Advanced section for risk weights, Z slider details
  - Make visible but collapsed by default

- [ ] **4.2d** Tables: sensible default columns, rest opt-in
  - **Add:** Column selector component
  - Default: Name, Algorithm, Risk, Confidence
  - Optional: Detection method, Location, Snippet, etc.

- [ ] **4.2e** Default sort: risk descending
  - **Verify:** All tables sort by risk by default
  - Most critical row appears first

**Implementation:**
```typescript
// Add ColumnSelector component
<DataTable
  columns={defaultColumns}
  optionalColumns={optionalColumns}
  defaultSort={{ field: 'risk', order: 'desc' }}
/>

// Add AdvancedPanel component
<Collapsible title="Advanced">
  <RiskWeightsConfig />
  <RuleToggles />
  <RawJSONView />
</Collapsible>
```

---

## §4.3: Plain Language

**Current Status:** Glossary exists, need inline tooltips

- [ ] **4.3a** Inline ⓘ tooltips for acronyms
  - **Add:** `<Tooltip />` component
  - CRQC, HNDL, ML-KEM, etc. get tooltips on first appearance

- [ ] **4.3b** Plain-English summary on findings
  - **Add:** Summary field to artefact cards
  - "This login service uses RSA-2048..."

- [ ] **4.3c** Glossary page ✅ **EXISTS**
  - Link from every tooltip

- [ ] **4.3d** Risk bands: word + colour + icon
  - **Verify:** CRITICAL 🔴, HIGH 🟠, MEDIUM 🟡, LOW 🟢
  - Never colour alone

- [ ] **4.3e** No raw enums on screen
  - **Verify:** HARDWARE_MODULE → "Hardware module"
  - Add humanize utility if needed

**Implementation:**
```typescript
// Add Tooltip component
<Tooltip content="CRQC: a cryptographically relevant quantum computer">
  CRQC
</Tooltip>

// Add RiskBadge component
<RiskBadge level="critical">
  <Icon name="alert-circle" />
  CRITICAL
</RiskBadge>

// Add humanize utility
const humanize = (enumValue: string) =>
  enumValue.toLowerCase().replace(/_/g, ' ')
    .replace(/\b\w/g, l => l.toUpperCase());
```

---

## §4.4: Actionable UI

**Current Status:** Needs primary action buttons

- [ ] **4.4a** Primary action on every finding
  - **Add:** Action button to artefact cards
  - View evidence / See recommendation / Assign / Accept risk

- [ ] **4.4b** Risk numbers paired with reason + next step
  - **Enhance:** Risk display to show "Why?" and "What to do?"

- [ ] **4.4c** "Top 5 things to fix" panel on dashboard
  - **Add:** Priority panel component
  - Most critical findings with clear actions

- [ ] **4.4d** Empty states teach, don't apologise
  - **Replace:** "No data" → "Run your first scan" CTA
  - Add helpful empty state components

**Implementation:**
```typescript
// Add PriorityPanel to Dashboard
<PriorityPanel
  title="Top 5 Things to Fix This Quarter"
  items={top5Critical}
  onAction={(item) => navigate(`/artefacts/${item.id}`)}
/>

// Add EmptyState component
<EmptyState
  title="No scans yet"
  description="Get started by scanning your first application"
  action={<Button onClick={startScan}>Run Your First Scan</Button>}
/>
```

---

## §4.5: Never Stare at Nothing

**Current Status:** Needs real-time progress

- [ ] **4.5a** Live progress with real percentage
  - **Add:** WebSocket integration for scan progress
  - "Scanning Java sources… 1,204 / 5,880 files"

- [ ] **4.5b** Partial results render during scan
  - **Add:** Streaming results to artefact table
  - Table fills as findings arrive

- [ ] **4.5c** Skeleton loaders, not spinners
  - **Verify:** Using Skeleton component ✅
  - Replace any spinners with skeletons

- [ ] **4.5d** Immediate feedback (<100ms)
  - **Add:** Toast notifications
  - Optimistic UI updates

- [ ] **4.5e** Errors state cause and fix
  - **Enhance:** Error messages
  - "Could not clone repo: auth failed. Add token in Settings"

**Implementation:**
```typescript
// Add useWebSocket hook for progress
const { progress } = useWebSocket(`/api/v1/scans/${scanId}/events`);

<ProgressBar
  percent={progress.percent}
  label={`${progress.stage} ${progress.current} / ${progress.total} files`}
/>

// Add Toast system
<Toast
  type="error"
  title="Scan Failed"
  message="Could not clone repo: authentication failed."
  action="Add deploy token in Settings → Credentials"
/>
```

---

## §4.6: Trust - Show Evidence, Admit Gaps

**Current Status:** Artefact detail page exists, enhance with evidence

- [ ] **4.6a** One click to source evidence
  - **Verify:** Artefact page shows code snippet ✅
  - Add syntax highlighting and file:line navigation

- [ ] **4.6b** Show confidence + detection method
  - **Verify:** Displayed on artefact cards
  - High / Medium / Low with method name

- [ ] **4.6c** Mosca verdicts show inputs (X, Y, Z)
  - **Add:** Expandable section showing calculation
  - "Z=12, Y=2035, X=financial → CRITICAL"

- [ ] **4.6d** Coverage gaps in UI
  - **Add:** Gaps panel to scan detail
  - "3 binaries stripped, could not analyze"

- [ ] **4.6e** Mark as false positive
  - **Add:** Review action button
  - Reason field + persists across rescans

**Implementation:**
```typescript
// Add Evidence section to ArtefactPage
<Evidence
  code={artefact.snippet}
  file={artefact.location.path}
  line={artefact.location.line}
  language={detectLanguage(artefact.location.path)}
/>

// Add Mosca calculation display
<MoscaCalculation
  x={risk.x_tier}
  y={risk.y_year}
  z={risk.z_assumption}
  result={risk.mosca_score}
  formula="Shows the arithmetic"
/>

// Add Review button
<ReviewDialog
  onSubmit={(reason) => markFalsePositive(artefactId, reason)}
/>
```

---

## §4.7: Navigation and Orientation

**Current Status:** Basic routing exists, needs enhancement

- [ ] **4.7a** Persistent left nav ✅ **EXISTS** (Shell.tsx)
  - Verify current location is highlighted

- [ ] **4.7b** Breadcrumbs on drill-down
  - **Add:** Breadcrumb component
  - Org → Application → Component → Artefact

- [ ] **4.7c** URL-addressable views
  - **Verify:** Filters/tabs in URL
  - Make shareable links work

- [ ] **4.7d** Browser back works correctly
  - **Test:** Modals/drawers don't trap
  - Fix any navigation issues

- [ ] **4.7e** Global search (/ or Ctrl-K)
  - **Add:** Command palette
  - Search any application, algorithm, artefact

- [ ] **4.7f** Max 3 clicks from dashboard
  - **Audit:** Navigation depth
  - Ensure key actions are quick

**Implementation:**
```typescript
// Add Breadcrumbs component
<Breadcrumbs>
  <Link to="/explorer">Applications</Link>
  <Link to={`/applications/${appId}`}>{appName}</Link>
  <span>{artefactName}</span>
</Breadcrumbs>

// Add CommandPalette (Ctrl-K)
<CommandPalette
  onSearch={(query) => searchEverything(query)}
  shortcuts={[
    { key: '/', label: 'Search' },
    { key: 'g d', label: 'Go to Dashboard' },
  ]}
/>
```

---

## §4.8: Consistency and Visual Language

**Current Status:** Needs design system documentation

- [ ] **4.8a** One risk colour scale everywhere
  - **Define:** CSS variables for risk colours
  - Critical: red, High: orange, Medium: yellow, Low: green

- [ ] **4.8b** Shared component library ✅ **STARTED**
  - Document all components
  - Ensure consistency

- [ ] **4.8c** Consistent iconography
  - **Add:** Icon mapping for asset types
  - Key 🔑, Certificate 📜, Algorithm 🔢, etc.

- [ ] **4.8d** Dates absolute and unambiguous
  - **Standardize:** YYYY-MM-DD format
  - Relative time as secondary ("3 days ago")

- [ ] **4.8e** Numbers formatted
  - **Add:** formatNumber utility
  - 12,480 not 12480, 2.3 GB not 2300000000

**Implementation:**
```css
/* Add to styles.css */
:root {
  --risk-critical: #ef4444;
  --risk-high: #f97316;
  --risk-medium: #eab308;
  --risk-low: #22c55e;
}
```

```typescript
// Add formatters
const formatDate = (iso: string) => {
  const date = new Date(iso);
  return date.toISOString().split('T')[0]; // 2026-03-14
};

const formatNumber = (num: number) =>
  new Intl.NumberFormat().format(num); // 12,480
```

---

## §4.9: Accessibility

**Current Status:** Needs accessibility audit

- [ ] **4.9a** WCAG 2.1 AA contrast
  - **Audit:** Check all colour combinations
  - Light and dark theme compliance

- [ ] **4.9b** Colour + text + icon (never colour alone)
  - **Verify:** Risk indicators have all three
  - Critical for colour-blind users

- [ ] **4.9c** Full keyboard operability
  - **Test:** Tab order, focus rings, Esc closes
  - Arrow keys in tables

- [ ] **4.9d** ARIA labels and live regions
  - **Add:** Screen reader support
  - Progress announcements

- [ ] **4.9e** Charts have text alternatives
  - **Add:** Data tables for all charts
  - Accessible alternatives

- [ ] **4.9f** Respects prefers-reduced-motion
  - **Add:** CSS media query handling
  - Disable animations when requested

**Implementation:**
```css
@media (prefers-reduced-motion: reduce) {
  * {
    animation-duration: 0.01ms !important;
    transition-duration: 0.01ms !important;
  }
}
```

```typescript
// Add ARIA to progress
<div role="status" aria-live="polite" aria-atomic="true">
  Scanning: {progress.current} of {progress.total} files
</div>
```

---

## §4.10: Performance

**Current Status:** Needs optimization for large datasets

- [ ] **4.10a** Artefact table smooth at 100k rows
  - **Add:** Virtual scrolling (react-window)
  - Pagination or infinite scroll

- [ ] **4.10b** Filter/search instant (<200ms)
  - **Add:** Debounced search
  - Client-side filtering for speed

- [ ] **4.10c** Mosca Z slider recalculates live
  - **Verify:** Immediate visual feedback
  - No lag when dragging

- [ ] **4.10d** Charts degrade at high cardinality
  - **Add:** Top-N + "Other" grouping
  - Max 20 slices, not 4,000

**Implementation:**
```typescript
import { FixedSizeList } from 'react-window';

<FixedSizeList
  height={600}
  itemCount={artefacts.length}
  itemSize={50}
  width="100%"
>
  {({ index, style }) => (
    <div style={style}>{artefacts[index].name}</div>
  )}
</FixedSizeList>
```

---

## §4.11: Onboarding

**Current Status:** Needs first-run experience

- [ ] **4.11a** First-run guided tour
  - **Add:** Interactive tour component
  - Highlight Dashboard, Explorer, Risk, Migration
  - Skippable, re-runnable

- [ ] **4.11b** Demo dataset in one click
  - **Verify:** Demo seed API exists ✅
  - Add prominent "Load Demo Data" button

- [ ] **4.11c** Contextual help (?) on visualisations
  - **Add:** Help icon with explainer
  - "How to read this chart"

- [ ] **4.11d** Scan wizard has sane defaults
  - **Simplify:** Minimal required fields
  - Launch with just target path/repo

**Implementation:**
```typescript
// Add Tour component
<Tour
  steps={[
    { target: '.dashboard', content: 'See your risk overview here' },
    { target: '.explorer', content: 'Browse all findings' },
    { target: '.mosca', content: 'Understand timeline risk' },
  ]}
  onComplete={() => markTourComplete()}
/>

// Add demo data button
<Button onClick={loadDemoData}>
  Load Demo Data
</Button>
```

---

## Implementation Priority

### Phase 1: Critical UX (Week 1)
1. Progressive disclosure (§4.2) - default sorts, column limits
2. Plain language (§4.3) - tooltips, humanized text
3. Actionable UI (§4.4) - primary actions, top 5 panel
4. Empty states (§4.4d) - helpful CTAs

### Phase 2: Trust & Evidence (Week 2)
1. Show evidence (§4.6) - code snippets, confidence
2. Live progress (§4.5) - WebSocket, streaming results
3. Navigation (§4.7) - breadcrumbs, command palette
4. Error handling (§4.5e) - helpful error messages

### Phase 3: Polish & Accessibility (Week 3)
1. Consistency (§4.8) - design tokens, formatters
2. Accessibility (§4.9) - WCAG audit, keyboard nav
3. Performance (§4.10) - virtual scrolling, debouncing
4. Onboarding (§4.11) - tour, demo data

---

## Summary

**Current State:** ~40% of §4 requirements implemented

**Exists:**
- Basic routing and pages
- Authentication
- Component library started
- Glossary page
- Skeleton loaders

**Needs Work:**
- Persona-based entry points
- Progressive disclosure enforcement
- Inline tooltips and plain language
- Primary action buttons
- Real-time progress (WebSocket)
- Evidence display enhancement
- Breadcrumbs and global search
- Accessibility audit
- Performance optimization
- Onboarding tour

**Estimated Effort:** 3-4 weeks to complete all §4 requirements
