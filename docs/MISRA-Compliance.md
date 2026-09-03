# MISRA C Compliance

wolfCOSE strives for MISRA C compliance and is checked in CI on every pull request. The project is not yet fully MISRA C:2023 compliant since there is no checker for 2023 that is publicly available yet. We do fully test and support the 2012 Misra-C standard. Full MISRA C:2023 verification requires commercial tooling (like LDRA, Polyspace, Cppcheck Premium). The current free tooling provides around 80% coverage across syntax, essential type, and data-flow rules.

## Coverage

### MISRA C:2012

Verified via cppcheck's MISRA addon (`--addon=misra`) with all wolfCOSE algorithm and feature macros defined. Covers ~65-75% of decidable MISRA C:2023 rules including:

- Syntax rules (comments, declarations, expressions)
- Control flow rules (goto, switch, loops)
- Declaration and type rules
- Pointer and array rules

**Workflow**: `.github/workflows/misra-2012.yml`

All wolfCOSE and wolfSSL feature macros are explicitly defined so cppcheck checks the full code path rather than enumerating wolfSSL's hundreds of platform `#ifdef` configurations. See [[Macros]] for the complete list.

### MISRA C:2023

MISRA C:2023 is essentially MISRA C:2012 plus Amendments 1-4. Since free tooling does not directly support MISRA C:2023, compliance is approximated using two approaches:

**Strict Compiler Warnings** 17 MISRA-adjacent GCC flags beyond the project's standard `-Wall -Wextra -Wpedantic -Wshadow -Wconversion`:

| Flag | MISRA Rule | Purpose |
|------|-----------|---------|
| `-Wcast-qual` | Rule 11.8 | Const qualifier preservation |
| `-Wstrict-prototypes` | Rule 8.2 | Function declaration completeness |
| `-Wmissing-prototypes` | Rule 8.2 | Missing function prototypes |
| `-Wold-style-definition` | Rule 8.2 | Old-style function definitions |
| `-Wdeclaration-after-statement` | Rule 8.x | C90-style declaration ordering |
| `-Wundef` | Rule 20.9 | Undefined macro in `#if` |
| `-Wfloat-equal` | Rule 13.4 | Float equality comparison |
| `-Wpointer-arith` | Rule 18.x | Pointer arithmetic safety |
| `-Wredundant-decls` | Rule 8.x | Redundant declarations |
| `-Wnested-externs` | Rule 8.x | Nested extern declarations |
| `-Wformat=2` | Rule 21.6 | Format string safety |
| `-Wformat-security` | Rule 21.6 | Format string security |
| `-Wlogical-op` | Rule 12.x | Logical vs bitwise operators |
| `-Wjump-misses-init` | Rule 15.1 | Goto skipping initialization |
| `-Wdouble-promotion` | Rule 10.x | Implicit float-to-double |
| `-Wnull-dereference` | Safety | Null pointer dereference |
| `-Wsign-conversion` | Rule 10.x | Signed/unsigned conversion |

**clang-tidy Checks** covers standard library safety (Amendment 3), deep data-flow analysis, and CERT C rules that map to MISRA 2023 logic:

| Check Category | Coverage |
|---------------|----------|
| `bugprone-*` | Unsafe patterns (buffer overflows, integer overflows, suspicious constructs) |
| `cert-*` | CERT C rules mapping to MISRA 2023 logic |
| `clang-analyzer-*` | Inter-procedural data-flow analysis, pointer tracking |
| `misc-*` | Miscellaneous safety checks (excluding `misc-include-cleaner`) |

**Workflow**: `.github/workflows/misra-2023.yml`

## Coverage Summary

| Area | cppcheck (2012) | Compiler Flags + clang-tidy (2023) | Commercial Tools |
|------|----------------|-----------------------------------|-----------------|
| Syntax Rules | High (~90%) | High (~95%) | 100% |
| Essential Types | Medium (~50%) | High (~80%) | 100% |
| Data Flow | Low (~30%) | Medium (~50%) | 100% |
| Std Lib Safety | Low (~20%) | Medium (~60%) | 100% |

## MISRA C:2012 Rule Enforcement

The MISRA C:2012 workflow does not suppress any project rule IDs. It retains
the raw analyzer output, separately reports approved deviations and proven
analyzer limitations, and fails every undeviated finding in `src/` or
`include/wolfcose/`. The remaining cppcheck suppressions only exclude generic
analyzer diagnostics and findings inside third-party wolfSSL headers.

The analyzer includes `tests/misra_consumer.c` as a downstream translation
unit. This gives public APIs and public constants a real external use for Rules
8.7 and 2.5 without linking analyzer-only code into the library. For Rule 2.5,
cppcheck does not count a macro used only by an `#if` or `#ifdef`; the report
classifier accepts that limitation only after finding the exact macro in a
tracked conditional preprocessing directive.

### Approved deviations

| ID | Rule | Location | Rationale and validation |
|----|------|----------|--------------------------|
| D-11.5-001 | 11.5 | `wolfCose_ForceZero` | Converting the caller's object pointer to a volatile character pointer is the standard C mechanism for securely erasing its object representation. Character access is alignment-safe and the function allocates no memory. `make zeroize-test`, `make zero-alloc-check`, and `make c99-check` validate the implementation. |
| D-19.2-001 | 19.2 | `WOLFCOSE_KEY.key` | The public, discriminated union preserves the established ABI and embedded-memory footprint. `kty` and `attachedType` govern member access. Replacing it with a structure would break ABI and increase RAM. The full tests exercise the supported members, and CI anchors the deviation to the exact union boundaries. |

`scripts/misra-deviations.json` identifies only these source locations. The
classifier also pins a hash of the public union declaration. It fails if an
expected diagnostic disappears, an anchor or approved declaration changes, or
an additional finding of either rule appears, so a deviation cannot silently
broaden or become stale.

## MISRA C:2023 Deviations (clang-tidy)

The following clang-tidy checks are suppressed in the MISRA 2023 workflow. GCC strict MISRA warnings are fully clean (0 warnings).

### bugprone-branch-clone: Identical Consecutive Switch Branches

**Location:** `src/wolfcose_alg.c` (algorithm dispatch switches)

**Justification:** Different COSE algorithms intentionally map to the same wolfCrypt value. For example, ES512 and EdDSA both use `WC_HASH_TYPE_SHA512`, and A128GCM/A192GCM share the same nonce length. The switch branches are not bugs; they represent distinct algorithm IDs with identical cryptographic parameters.

### bugprone-easily-swappable-parameters: Adjacent Parameters of Similar Types

**Location:** Multiple public API functions

**Justification:** Advisory warning about adjacent function parameters of the same type (e.g., `size_t payloadLen, size_t detachedLen`). Fixing requires reordering or wrapping parameters, which would break the public API. The parameter ordering follows RFC 9052 structure conventions.

## Examples and Test Code

`examples/` and `tests/` are runnable demonstration and test programs, not part of the shippable library, and are held to the same style rules where it keeps them useful as reference implementations. They are clean of the rules the library observes (no `goto`, fixed-length-coordinate checks, const-qualified literal payloads, braced statement bodies, unsigned size arithmetic, explicit precedence). The remaining deviations are inherent to runnable demos:

### Rule 21.6: Standard I/O (and 17.7 on its return value)

**Location:** `examples/`, `tests/`.

**Justification:** Demos and test harnesses print human-readable status and PASS/FAIL to the console with `printf`/`fprintf`; the ignored return value (Rule 17.7) is part of the same console-output use. A real integration replaces this one call with a platform output routine. Library code under `src/` uses no standard I/O.

### Rule 15.5: Multiple return / single point of exit

**Location:** `examples/`, `tests/`.

**Justification:** Demonstration code uses early returns for linear, readable top-to-bottom flow. The library itself observes single-exit with cascading `if (ret == 0)` and a single `return`.

### Rule 2.5: Unused macro definitions

**Location:** `examples/`, `tests/`.

**Justification:** Same false positive as the library: CI passes explicit `-D` feature flags so cppcheck checks one code path, which makes the guarded-away feature `#define`s look unused.

### Rules 8.6 / 5.9 / 8.9: External/internal identifier definitions

**Location:** `examples/`.

**Justification:** Each demo is a standalone program with its own `main` and `demo_*` helpers. cppcheck reports these when scanning all demo translation units in a single pass; each program links independently, so there is no real multiple-definition.

## Fully Compliant Rules (Notable)

| Rule | Status | Notes |
|------|--------|-------|
| Rule 15.1 (no goto) | Compliant | All functions use cascading `if (ret == WOLFCOSE_SUCCESS)` with a single `return ret` |
| Rule 15.5 (single exit) | Compliant | All functions have exactly one return statement |
| Rule 17.2 (no recursion) | Compliant | CBOR decoder uses iterative traversal with a bounded stack (`WOLFCOSE_CBOR_MAX_DEPTH`) |
| Rule 17.7 (check returns) | Compliant | All return values checked or explicitly cast to `(void)` |
| Rule 12.1 (explicit precedence) | Compliant | All `&&`/`||` operands and mixed arithmetic explicitly parenthesized |
