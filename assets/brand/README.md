# Interface assets

This directory contains the repository's SVG marks, lockups, social-card artwork,
plain-text mark, and color data.

| File | Use |
|---|---|
| `logo-mark.svg` | Primary mark |
| `logo-mark-brass.svg` | Alternate mark |
| `logo-wordmark.svg` | Wordmark |
| `logo-lockup.svg` | Horizontal mark and wordmark |
| `logo-lockup-stacked.svg` | Stacked mark and wordmark |
| `favicon.svg` | Small square icon |
| `og-card.svg` | Repository social-card artwork |
| `ascii.txt` | Plain-text terminal mark |
| `palette.json` | Asset color values |

Runtime TUI colors and product strings are defined in
`src/dietrich/tui/theme.py` and `src/dietrich/brand.py`. Asset changes should keep
those files consistent where the same value is used.
