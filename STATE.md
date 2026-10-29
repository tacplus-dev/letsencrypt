# State: letsencrypt

Overwritten to stay current (loopers and agents). Last updated: 2026-10-29 by the looper (#8).

- **Version / line:** unreleased (no vX.Y.Z tag yet, #3); tacplus floor 2.5 (tacplus.yaml, #8). Stratum, one of
  the `depends`, needs 2.5.
- **Works:** `just gates` (generate, go.mod/go.sum tidy, gofmt, build, vet, test) passes with tacplus 2.5.1 when
  the compiler has a Go toolchain on its PATH.
- **Released / deployed:** nowhere yet.
- **Known gaps:** the published `tacplus:2.5` image has no `go`, so generation fails at goimports there
  (tacplus-dev/tacplus#188); certificates still go through the event bus, not straight to Stratum (#2); SeaBeam
  module paths and registries (#4); base image (#5); `.gitlab-ci.yml` is the SeaBeam pipeline and reads a
  `tacplus-version:` key tacplus.yaml no longer has (see PROPOSALS.md).
- **Blocked on:** tacplus-dev/tacplus#188 (gates with the published compiler image).
