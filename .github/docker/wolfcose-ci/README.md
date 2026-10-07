# wolfCOSE CI image

Linux workflows use `ghcr.io/wolfssl/wolfcose-ci:latest`. Native macOS builds
retain their Homebrew dependencies. The image contains the C compiler matrix,
analysis and coverage tools, Go 1.24.x, stable Rust, and Python 3.12 peers.
The GitHub CLI supports the existing wiki publishing action.
Python interop requirements come from the existing pinned requirements file;
Semgrep and Codespell use a separate environment.

From the repository root:

```sh
docker build --platform linux/amd64 \
    -f .github/docker/wolfcose-ci/Dockerfile -t wolfcose-ci .
docker run --rm --platform linux/amd64 wolfcose-ci wolfcose-ci-smoke
```

The Dockerfile-specific ignore file restricts the build context to image assets
and Python interop requirements. Add shared dependencies here instead of
installing them in workflow jobs. Go patch releases, stable Rust, Semgrep, and
Codespell are resolved when the image is rebuilt.

`publish-ci-image.yml` validates image changes in PRs without publishing. In
`wolfSSL/wolfCOSE`, relevant pushes to `main` and manual dispatches publish
`latest` and `sha-<commit>` tags. Publication is serialized and uses the
repository's `GITHUB_TOKEN`. The GHCR package must be public so fork PRs can
pull anonymously.

After publishing, a container job repeats the smoke checks in the GitHub runner
environment and exercises the wiki action in dry-run mode without publishing
documentation.

During first-time bootstrap, the upstream `ci/ghcr-ci-image` branch also
publishes. Remove that trigger after the image is public and before merging.
Consumers should never fall back to building the image or installing packages.

Linux wolfSSL caches use the `wolfcose-ci-v1` prefix to separate them from
previous host builds. Bump this prefix if an image change makes cached builds
incompatible. To roll back, point consumers at a previously published
`sha-<commit>` tag.
