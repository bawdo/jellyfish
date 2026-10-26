# Contributing

Thanks for taking an interest. jellyfish is small and maintained by one
person, so the process is light.

## Before you start

Open an issue for anything bigger than a typo or a one-line fix, so the
approach can be agreed before you spend time on it. Security problems go
through [SECURITY.md](SECURITY.md), not the issue tracker.

## Making a change

1. Fork and branch from `main`.
2. Run `make pre-ci` before pushing. It mirrors the GitHub Actions checks
   (format, tests with the race detector, lint, coverage, build,
   `govulncheck`, a CLI smoke test and the changelog check).
3. Add a line under `[Unreleased]` in `CHANGELOG.md` for anything a user
   would notice. Follow the existing Keep a Changelog headings.
4. Open a pull request. CI must pass before it can be merged. There is no
   reviewer requirement, but expect questions.

Commits are signed and written in the past tense with a subject of about
50 characters. Australian English in prose.

## How releases happen

Releases are cut by `.github/workflows/release.yml` when a merge to `main`
moves the newest `## [X.Y.Z] - YYYY-MM-DD` heading in `CHANGELOG.md` to a
version with no published release. To release:

1. Rename `[Unreleased]` to the new version and date, and add the
   `[X.Y.Z]: compare` link at the bottom.
2. Start a fresh `[Unreleased]` section above it.
3. Merge. The workflow runs CI, tags the merge commit (or, if you tagged
   `vX.Y.Z` by hand, uses that commit), builds the darwin binaries, attests
   the checksums and publishes the release with that changelog section as
   the notes. A draft release of the same name is replaced.

A pull request whose changelog version is behind the latest tag, or has a
malformed date or no link reference, fails the `Changelog` check.
