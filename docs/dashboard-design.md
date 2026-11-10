# Dashboard design choices

Why the dashboard looks and behaves the way it does. Each choice follows a known usability rule; most were checked by measuring, not by eye.

## Who it's for

One IT person at a desk, opening it a few times a week to answer three questions fast: *Is anything wrong? What should I do first? Did my fix work?* So it is plain on purpose: clear beats pretty for a work tool.

## The rules behind it

| Rule (HCI) | Where you see it |
|---|---|
| **Visibility of system status**: always show what's going on | Moving bar at the top during any request; "Scanning… 12s" counts up because a scan takes 10–25 s (after ~10 s people think an app froze); "Last scan: 5 min ago"; a ⚠ and a sentence when the last scan is older than 26 hours |
| **Error prevention**: stop mistakes before they happen | Every Fix and Delete shows a **preview** of the exact change first; Delete has a red warning; when a confirm popup opens, the keyboard focus is on **Cancel**, so pressing Enter can't delete by accident; the Ignore button stays off until a reason is typed |
| **Help people recover from errors** | If loading fails, the table says what went wrong in plain words and offers **Try again**; error messages stay until closed (good news disappears by itself after 5 s) |
| **User control and freedom**: a way back | Fix keeps the resource; Ignore is undone by removing the tag; Delete, the one action with no way back, is the one that asks twice |
| **Recognition, not recall**: don't make people remember | Each button says what it does when the mouse rests on it; the AWS ID is shown under each name; CIS labels explain the rule in plain English |
| **Match what people expect** | The grade is a big letter with a score bar, not a letter in a circle (that pattern means "profile picture"); the header looks like the AWS console |
| **Consistency** | One word for one thing: "findings" on every screen and in the emails |
| **Truthful feedback** | The result popup says "3 done, 1 failed", never just "Done"; failures are listed first |
| **Grouping (Gestalt: common region)** | Grey page, white cards: the table, the summary and each Report section are each one box |
| **Scanning, not reading** | Summary box is one label and one value per row; rows are sorted by risk, then cost; "for 3 days" under the status shows what has waited longest |

## Colour

Colour is only used when it means something. If everything is coloured, nothing stands out.

| Colour | Meaning |
|---|---|
| Red / amber / grey | Risk: HIGH / MEDIUM / LOW (badge, left edge of the row, grade) |
| Green | Good: grade A, money saved, "OK" |
| Blue (orange in dark mode) | Something you can click |
| Everything else | Black, grey, white |

- **Never colour alone.** Every colour has words next to it (HIGH, not just red), because about 1 in 12 men are colour-blind.
- **Delete is quiet in the rows** (red words only). A column of loud red buttons would compete with the red that marks HIGH-risk rows. The filled red button appears in the confirm popup, where the decision is made.
- **Contrast is measured.** Every text colour has at least 4.5:1 contrast with its background in both themes (WCAG AA, the usual standard for small text). The lowest on the page is 4.8:1.
- **Dark mode** uses the AWS console's navy and orange. A theme is just a second list of values for the same colour variables in `style.css`.

## Access

- Everything works with the keyboard: Tab reaches every button and CIS label, with a visible outline.
- Tooltips open on hover, on keyboard focus and on tap, and close with Esc.
- Checkboxes and icon buttons have labels for screen readers; messages are announced.
- On a phone the summary moves above the table, and Fix / Delete / Ignore stay pinned at the right while the row scrolls under them.

## Left out on purpose

Charts beyond the history bars, animations, per-row icons, a settings page, filters. With five checks and a handful of findings they would be decoration. Filters and an Un-ignore button are listed as future work.
