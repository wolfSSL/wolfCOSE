# wolfCOSE CI image

Linux workflows pin `ghcr.io/wolfssl/wolfcose-ci` by its immutable image digest.
Native macOS builds retain their Homebrew dependencies. The image contains the
C compiler matrix, analysis and coverage tools, Go 1.24.x, stable Rust, and
Python 3.12 peers.
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

In `wolfSSL/wolfCOSE`, `publish-ci-image.yml` runs on relevant pushes to
`main` and manual dispatches targeting `main`. Publication is restricted to
`refs/heads/main`. It builds and smoke-tests the image, then publishes
`latest` and `sha-<commit>` tags. Publication is serialized and uses the
repository's `GITHUB_TOKEN`. The GHCR package must be public so fork PRs can
pull anonymously.

After publishing, a container job uses the build's output digest to repeat the
smoke checks in the GitHub runner environment and exercises the wiki action in
dry-run mode without publishing documentation.

Consumers should never fall back to building the image or installing packages.

Container jobs trust the mounted GitHub workspace after checkout so Git can
read a repository owned by the host runner. Their explicit Bash command keeps
the previous host shell's error behavior.

Linux wolfSSL caches use the `wolfcose-ci-v1` prefix to separate them from
previous host builds. Bump this prefix if an image change makes cached builds
incompatible.

To adopt a rebuilt image, inspect its `sha-<commit>` tag with
`docker buildx imagetools inspect` and copy the reported image digest into the
consumer workflows in a reviewed change. The publisher's smoke job tests the
new digest immediately, while consumer jobs keep using their reviewed digest.
To roll back, restore the previous digest in those workflows.
