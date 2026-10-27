# Roadmap: letsencrypt

Owned by Jody; changed only by an agent at Jody's request. Loopers propose in PROPOSALS.md.

## Now
Obtains and renews TLS certificates from Let's Encrypt over ACME (HTTP-01).
Ported from schematic 2026-10-23. Unreleased; tacplus floor 2.4 (declared in tacplus.yaml; #1 still open).

## Next
- Nothing unblocked; see Later.

## Later
- Declare the tacplus floor 2.4 (#1), blocked by tacplus-dev/tacplus#188, tacplus-dev/tacplus#189
- Work without SeaBeam: no gitlab.com/seabeam paths, sources or registries (#4), blocked by #1
- Add a `gates` recipe to the justfile (#6), blocked by #1
- Base image alpine:3.22 to 3.24 (#5), blocked by #6
- Write certificates to Stratum directly, not through the event bus (#2), blocked by tacplus-dev/stratum#2, #1
- Release v0.1.0 and publish its image (#3), blocked by tacplus-dev/looper#12 (needs Jody's decision), #1
- Gateway keeps its Let's Encrypt certificate across a kernel restart (tacplus-dev/roadmap:decisions/tacplus-dev-stable-gate-2026-10-25.md)
- The public name's certificate fails over with the cluster, in region failover (tacplus-dev/roadmap:decisions/stratum-per-tenant-2026-10-25.md)

## Not doing
- Nothing recorded yet.
