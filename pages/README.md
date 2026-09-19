# Pahlevan GitHub Pages

The published site: <https://obsernetics.github.io/pahlevan/>

## What is hand-written and what is generated

Two of these files are designed by hand. The rest are derived from the
repository, because a fact with two copies drifts, and on this site it did:
the changelog page went on badging 3.3.2 as the current release with no 3.3.3
article at all, while the version strings around it were already correct.

```
pages/
├── index.html            # hand-written: the landing page and its inline architecture SVG
├── changelog.html        # hand-written, except the release articles (generated)
├── docs/                 # GENERATED from docs/*.md - do not edit
│   ├── index.html        #   the documentation index
│   ├── <topic>.html      #   one page per docs/<topic>.md
│   └── assets/           #   diagrams the documents embed
├── assets/               # hand-written CSS, JS, icons; demo.gif is copied from docs/
└── charts/               # the Helm repository (packaged by the release workflow)
```

Nothing under `pages/docs/`, and nothing between the
`<!--pahlevan:sitegen releases-->` markers in `changelog.html`, should be
edited by hand: the next generator run overwrites it.

## The two generators

| Command | Owns |
|---|---|
| `go run ./hack/pagesync -write` | individual borrowed values inside `<!--pahlevan:sync ...-->` spans: the release version, the benchmark counts, the demo GIF |
| `go run ./hack/sitegen -write` | whole pages: every `docs/*.md`, the documentation index, and the release articles built from `CHANGELOG.md` |

Both have a `-check` that exits non-zero when the published site no longer
matches its sources, and both run on every pull request that touches a source
they read. `make pages-sync` runs both; `make pages-check` checks both.

Adding a document is enough: drop a `docs/<topic>.md` in, run `make site`, and
it is published, indexed and linked. A test iterates the real directory, so a
document that produces no page fails the build rather than quietly existing
only on GitHub.

## Local development

```bash
cd pages/
python3 -m http.server 8000
# http://localhost:8000
```

Edit `assets/css/main.css` for styling - the generated documentation pages use
the same stylesheet as the hand-written ones on purpose, so a change to the
site's look reaches all of them. Bump the `?v=N` cache buster in `index.html`,
`changelog.html` and `hack/sitegen/layout.go` together when the stylesheet
changes, or returning visitors keep the old one.

## Deployment

`.github/workflows/pages.yml` deploys on a push to `main`, on a published
release, weekly, and on demand. It refuses to deploy from a pull request, so a
fork cannot publish. Before the upload it re-runs both generators, so the
published site matches the repository even if a change reached `main` without
one.

## Helm repository

The site also serves the chart repository:

- Repository: `https://obsernetics.github.io/pahlevan/charts`
- Index: `https://obsernetics.github.io/pahlevan/charts/index.yaml`
