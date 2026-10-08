# wolfCOSE for STM32Cube

wolfCOSE is a zero-allocation C implementation of CBOR (RFC 8949) and COSE
(RFC 9052/9053) built on top of wolfCrypt. It ships as an STM32Cube pack,
`I-CUBE-wolfCOSE`, which provides wolfCOSE as an STM32 middleware and depends
on the wolfSSL pack (`I-CUBE-wolfSSL`) for wolfCrypt.

This directory holds the files the pack builds from:

- `wolfcose_test.c` / `wolfcose_test.h`: a self test that runs a `COSE_Sign1`
  ES256 sign and verify and prints the result. It is built by the pack `Test`
  component. Call `wolfCOSETest()` from your application once the clocks and
  console are initialized; it returns `0` on success.
- `default_conf.ftl`: the STM32CubeMX configuration template for the pack.

## Dependency

Install the wolfSSL pack (`I-CUBE-wolfSSL`, version 5.9.2 or later) first and
enable `wolfCrypt: Core`. wolfCOSE uses wolfCrypt for hashing, signing, and AEAD.
See the
[wolfSSL STM32Cube README](https://github.com/wolfSSL/wolfssl/blob/master/IDE/STM32Cube/README.md)
for the wolfSSL pack documentation and install instructions.

## Enabling in STM32CubeMX

1. `Help`, `Manage embedded software packages`, `From Local...` and install
   the wolfSSL pack, then this wolfCOSE pack.
2. Enable the RNG peripheral under `Pinout & Configuration`, `Security`, `RNG`.
   Signing needs entropy, and `wc_GenerateSeed()` fails without it.
3. In the project `.ioc`, open `Software Packs`, `Select Components`, expand
   `wolfCOSE` and check `Core` (and `wolfSSL`, `wolfCrypt: Core`). To run the
   on device self test, also check `wolfCOSE` `Test`.
4. In the `Software Packs` configuration category, enable the wolfCOSE pack.
5. Generate code and build.

## Configuration

wolfCOSE is configured through the wolfSSL `user_settings.h` (included before
`wolfcose/settings.h`). Algorithm support such as `WOLFCOSE_ENABLE_ES384`,
`WOLFCOSE_ENABLE_ES512`, and `WOLFCOSE_ENABLE_MLDSA` requires the matching
wolfCrypt features (`HAVE_ECC`, `WOLFSSL_SHA384/512`, `WOLFSSL_HAVE_MLDSA`).

See the wolfCOSE `examples/` for sign1, mac0, and encrypt0 usage, and the
[STM32Cube manual page](https://www.wolfssl.com/documentation/manuals/wolfcose/STM32Cube.html) for
the full walkthrough including a ready to run NUCLEO-H563ZI project.
