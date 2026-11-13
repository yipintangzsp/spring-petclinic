# Registry controller ARM64 recovery

The old `goharbor/harbor-registryctl:2.14.2` name was a locally imported ARM64
image, not a reproducible upstream tag. Replacing it with upstream `v2.14.2`
introduced an x86 binary that crashes under this host's QEMU. Do not alias the
upstream AMD64 image to the old name again.

Recovery candidate: compile `./registryctl` from the unmodified official
`goharbor/harbor` `v2.14.2` source under `src/`, using `CGO_ENABLED=0 GOOS=linux
GOARCH=arm64 go build -mod=readonly -trimpath`. Retain the source archive SHA256,
compiler identity and `go version -m` output alongside the resulting binary hash.
Package with `Dockerfile.registryctl-arm64` and the existing public CA bundle.
The controller implements registry storage operations in Go; it does not launch
an external registry executable. Existing registry configuration, auth secrets,
mounts and UID 10000 are reused. This candidate has no shell or startup package
installation. Additional private CA trust would require explicit bundle assembly
before using internal HTTPS; the current deployment uses HTTP internally.

Before changing the deployment, save its configuration and verify the candidate
starts with the existing configuration. Pin the resulting image digest. Verify
both registry ports have ready endpoints, controller health responds, and a full
Jenkins push/scan passes. Keep the old image/configuration for rollback. Until
those checks pass this is a recovery candidate, not an accepted platform release.

2026-10-22: candidate built with Go1.25.3 (CGO disabled), source and binary SHA256 and compiler module inventory preserved in private recovery evidence. Isolated controller health returned HTTP200/healthy. Deployment pinned to sha256:4e213a9725d3300d6e4c80c2d815ed51f20c76fbb5e803e34152c40418508e92, registry endpoint recovered. Apply the adjacent strategic merge patch after checking the existing Deployment identity. Full pipeline verification remains required; this is not a zero-vulnerability claim.
