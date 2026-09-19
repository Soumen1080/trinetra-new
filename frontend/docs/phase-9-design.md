# Phase 9 design specification

This is the design artefact for Phase 9. It names the user for every core
screen, the first question that screen must answer, and the deliberately small
first view before a user drills into a finding.

## Personas and 10-second questions

| Screen | Primary persona | Question answered in 10 seconds | Primary action |
|---|---|---|---|
| Dashboard | Executive / CISO | "How exposed are we, and what do we fix first?" | Open the highest-risk finding |
| Scan progress | Security analyst | "Is this working, and what has it found already?" | Open live findings |
| CBOM Explorer | Security analyst | "Which findings are real and which matter first?" | Inspect evidence |
| Artefact detail | Developer / app owner | "What is wrong here and how do I change it?" | See recommendation / correct context |

Role defaults keep this orientation: admin and viewer start on Dashboard;
analysts start on Explorer. A persistent navigation rail keeps every surface no
more than two interactions away.

## Wireframes

### Dashboard — executive / CISO

```
┌ Navigation ─────┬ Posture at a glance ──────────────────────────────┐
│ Overview        │ [Total] [Quantum exposed] [Critical] [Safe] [Mosca]│
│ Scans           │ Each number says what it means, not just the count │
│ Explorer        ├ Top 5 things to fix this quarter ──┬ Distribution ─┤
│ Glossary        │ plain action → evidence             │ accessible text│
│                 ├ At-risk applications ──────────────┴ Scan history ─┤
└─────────────────┴───────────────────────────────────────────────────┘
```

### Scan progress — security analyst

```
Target field → Launch
  [ 42% ] Scanning source files · 1,204 files · 18 findings
  [Open live findings]              [Show activity log]
  partial findings table (already populated while the scan runs)
```

### Explorer — security analyst

```
Search /  Filters with live counts     Risk-sorted table
                                     Critical ●  RSA-2048 …
                                     Needs context ◌  TLS …
                         one click → detail drawer
```

### Artefact drawer — developer / app owner

```
Plain sentence: why this needs attention
Evidence (file:line)  |  Mosca X + Y > Z, with all inputs
Recommendation        |  confidence and scanner shown openly
Primary action: correct context / view recommendation
```

## Token decisions

Risk is never colour-only: every status has a label and glyph. The same tokens
drive tiles, badges, table rows and chart alternatives.

| Token | Meaning | Light / dark value |
|---|---|---|
| `--risk-critical` | P0 / immediate action | `#b42318` / `#ffb4ab` |
| `--risk-high` | P1 / planned action | `#b54708` / `#ffb77c` |
| `--risk-medium` | P2 / monitor | `#1769aa` / `#a7d0ff` |
| `--risk-context` | unassessed / needs input | `#6941c6` / `#d9b8ff` |
| `--risk-info` | policy-decided / library | `#475467` / `#cbd5e1` |

The spacing scale is 4 / 8 / 12 / 16 / 24 / 32 / 48 px, the body text minimum
is 16 px, and all controls have a visible focus ring. Asset kinds use the same
text glyph plus word everywhere: algorithm `◇`, key `⌘`, certificate `▧`,
library `▤`, hardware `▣`, cloud `☁`.

## Paper walkthrough decisions incorporated

- The dashboard is capped at five headline tiles; unassessed work is visible,
  never smuggled into low risk.
- The scan page poll-falls-back when WebSocket delivery is unavailable; silence
  is labelled as a connection issue rather than as scan failure.
- The Explorer exposes only filters the API can apply. Unsupported bulk actions
  are deliberately absent rather than decorative controls.
- A missing measure says "Not measured" plus why, never `0` or a blank meter.
