#!/bin/bash
# Exercise the installed toolchains before an image is published.
set -euo pipefail

smoke_dir=$(mktemp -d)
trap 'rm -rf "$smoke_dir"' EXIT
cat > "$smoke_dir/main.c" <<'EOF'
int main(void)
{
    return 0;
}
EOF

for compiler in gcc gcc-11 gcc-12 gcc-13 clang clang-14 clang-15 clang-17; do
    "$compiler" --version | head -n 1
    "$compiler" -std=c99 -Wall -Wextra -Werror "$smoke_dir/main.c" \
        -o "$smoke_dir/compiler-test"
    "$smoke_dir/compiler-test"
done

test "$(cppcheck --version)" = 'Cppcheck 2.13.0'
cppcheck --addon=misra --error-exitcode=1 "$smoke_dir/main.c"
for tool in autoconf automake libtool pkg-config clang-tidy scan-build \
            lcov bc valgrind git gh curl jq zip unzip; do
    command -v "$tool"
done
pkg-config --exists openssl
go version
rustc --version
cargo --version
python -c 'import sys; assert sys.version_info[:2] == (3, 12); import cbor2, cwt, cryptography, pyhpke'
python -m pip check
/opt/ci-tools/bin/python -m pip check
semgrep --version
codespell --version
