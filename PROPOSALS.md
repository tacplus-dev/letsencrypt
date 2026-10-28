# Proposals: letsencrypt

Written by loopers. Each proposal: what, why, links. Jody promotes accepted ones into ROADMAP.md (via an agent);
the looper then marks it `promoted` or `declined` here with the date.

## Open
- **<title>** (<date>, <issue/run link>): <what and why>
- **govulncheck in the gates** (2026-10-28, #7): add a `vulncheck` recipe (`govulncheck ./...` with `model/`
  generated) to `just gates`, or to CI, so reachable advisories fail the build when they are introduced. As it is,
  they are found only by the nightly scan: #7 found 10 reachable ones (incl. the gRPC auth bypass GO-2026-4762).
  It needs a pinned govulncheck version and network access to vuln.go.dev wherever the gates run.

## Promoted / declined
