# Building and publishing the wolfCOSE manual

The top-level `docs/*.md` files are the manual source, one per page in
`mkdocs.yml`. The adapter in `tools/docs_manual.py` passes those pages to the
shared MkDocs theme and Pandoc/LaTeX PDF rules in
[`wolfSSL/documentation`](https://github.com/wolfSSL/documentation). Keep manual
content and its navigation in wolfCOSE; generated files stay under `build/`.

Anything that is not a manual page goes under `docs/dev/`: maintainer notes
(like this file), drafts, scripts, or diagrams not referenced by a page.
`mkdocs.yml` (`exclude_docs`) and the adapter (`tools/docs_manual.py`) keep that
directory out of the published HTML and PDF. Never place a non-manual file
directly in `docs/`: the build requires every top-level `docs/*.md` to be a page
in `mkdocs.yml`, so a stray file there fails the build.

## Local build

Clone the documentation build tools at the revision used by wolfCOSE CI:

```sh
git clone --recurse-submodules https://github.com/wolfSSL/documentation.git build/documentation
git -C build/documentation checkout "$(cat tools/docs-manual/documentation-rev)"
docker build --pull -t wolfcose-docs:local docker/docs
docker run --rm --user "$(id -u):$(id -g)" --env HOME=/tmp \
    --mount "type=bind,source=$PWD,target=/work/wolfCOSE" \
    --workdir /work/wolfCOSE wolfcose-docs:local \
    python3 tools/docs_manual.py build \
        --documentation-root /work/wolfCOSE/build/documentation \
        --source-root /work/wolfCOSE --target all
```

The outputs are `build/documentation/wolfCOSE/html/` and
`build/documentation/wolfCOSE/wolfCOSE-Manual.pdf`. The container includes
MkDocs, Pandoc, LaTeX, and the fonts used by the shared build rules. On a
wolfCOSE pull request, `docs-site.yml` checks out the pinned documentation
revision, builds both outputs, runs MkDocs in strict mode, and uploads them as
one artifact. It also runs after documentation changes merge to `main`.
CI pulls the versioned builder image from GHCR, or builds it from
`docker/docs/` if that image is unavailable. No host package installation or
website credentials are needed for this check.

For an HTML preview, first run the build above, then run:

```sh
docker run --rm --user "$(id -u):$(id -g)" --env HOME=/tmp -p 8000:8000 \
    --mount "type=bind,source=$PWD,target=/work/wolfCOSE" \
    --workdir /work/wolfCOSE/build/documentation/wolfCOSE \
    wolfcose-docs:local mkdocs serve -a 0.0.0.0:8000 -f mkdocs.yml
```

## Website update

The one-time integration in `wolfSSL/documentation` adds a `wolfCOSE` manual
target beside wolfBoot and wolfHSM. It clones `wolfSSL/wolfCOSE` **main**, runs
the adapter from that checkout, and exports `wolfCOSE-html/` and
`wolfCOSE-Manual.pdf` through the documentation repository's existing Docker
build. Merge the wolfCOSE adapter before that integration so its source is
available on `main`.

After both changes are merged, the existing nightly documentation build should
pick up `wolfcose` through the documentation repository's `all` target. No
manual trigger is needed for the normal update. Check the first nightly result
at `https://www.wolfssl.com/documentation/manuals/wolfcose/` and its
`wolfCOSE-Manual.pdf`. The website upload rules are outside these public
repositories; if the nightly publishes an explicit list of manuals instead of
all build output, that list will need a one-time addition. Subsequent merged
wolfCOSE documentation changes are read from wolfCOSE `main` on the next
nightly run. Pull requests only build review artifacts.
