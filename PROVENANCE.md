# Provenance

Copied **wholesale** on 2026-10-23 from `gitlab.com/seabeam/schematic/platform/services/letsencrypt` at commit
`1c30faf` (its own nested git repository; history carried over), with `proto/services/letsencrypt.proto` and
`proto/dependencies.yaml` from `platform/proto` at `ca7c322` on branch `big8-p1-messaging`. Build outputs not copied.

Jody, 2026-10-23: *"We will copy kernel over to its github home and only make changes to it. we will
keep these as ships in the night for now. For the new stuff we want to do it the right way."* and
*"the following will also need to be ported over to tacplus-dev ... blobstore gateway kmaker letsencrypt
eventbus oauth"*. The private copy runs the launch fleet unchanged; new-design changes land here.

Divergences: headers in tacplus.yaml (Jody Scott, Apache-2.0; LICENSE added); `src: proto` (this repo
holds the service's own proto); `proto/registry.yaml` is a lock of github.com/tacplus-dev/registry.
