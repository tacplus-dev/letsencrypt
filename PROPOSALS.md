# Proposals: letsencrypt

Written by loopers. Each proposal: what, why, links. Jody promotes accepted ones into ROADMAP.md (via an agent);
the looper then marks it `promoted` or `declined` here with the date.

## Open
- **<title>** (<date>, <issue/run link>): <what and why>
- **govulncheck in the gates** (2026-10-28, #7): add a `vulncheck` recipe (`govulncheck ./...` with `model/`
  generated) to `just gates`, or to CI, so reachable advisories fail the build when they are introduced. As it is,
  they are found only by the nightly scan: #7 found 10 reachable ones (incl. the gRPC auth bypass GO-2026-4762).
  It needs a pinned govulncheck version and network access to vuln.go.dev wherever the gates run.
- **`.gitlab-ci.yml` cannot find its compiler line** (2026-10-29, #8): its `compute-image` and
  `compute-validate-image` jobs read `tacplus-version:` from tacplus.yaml, which now declares only `tacplus:
  "2.5"`, so every tagged or proto-validate pipeline would stop at "tacplus-version not set". The jobs also pull
  `seabeam/schematic/tacplus/tacplus-M-N` from the SeaBeam registry. Fold it into #4 (work without SeaBeam) or the
  release pipeline of #3: build with `ghcr.io/tacplus-dev/tacplus/tacplus:<tacplus:>` like the looper does.
- **ROADMAP.md "Now" names floor 2.4** (2026-10-29, #8): the floor is 2.5 since #8; the line "Unreleased; tacplus
  floor 2.4" and the Later entry for #1 ("Declare the tacplus floor 2.4") are stale. For Jody to have changed.

## Promoted / declined
