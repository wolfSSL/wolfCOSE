# STM32Cube

wolfCOSE ships as an STM32Cube pack, `I-CUBE-wolfCOSE`, so it drops into any
STM32CubeMX or STM32CubeIDE project without manual source integration. The pack
provides wolfCOSE as an STM32 middleware and uses the wolfSSL pack
(`I-CUBE-wolfSSL`) for all cryptography.

Supported cores: Cortex-M0, M0+, M3, M4, M7, M23, M33, M55, and STM32MP1.

## Prerequisites

- STM32CubeMX, plus STM32CubeIDE or another toolchain to build.
- The wolfSSL pack, `I-CUBE-wolfSSL` 5.9.2 or later. wolfCOSE depends on
  wolfCrypt for hashing, signing, and AEAD.
- A board with a hardware RNG and a UART for console output.

## Install the packs

1. Download the wolfSSL pack
   ([I-CUBE-wolfSSL.pack](https://www.wolfssl.com/files/ide/I-CUBE-wolfSSL.pack))
   and the wolfCOSE pack
   ([I-CUBE-wolfCOSE.pack](https://www.wolfssl.com/files/ide/I-CUBE-wolfCOSE.pack)).
2. In STM32CubeMX, open `Help`, `Manage embedded software packages`,
   `From Local...`, and install the wolfSSL pack first, then the wolfCOSE pack.

## Add wolfCOSE to a project

1. Open or create a project `.ioc` for your board.
2. Enable the RNG peripheral under `Pinout & Configuration`, `Security`, `RNG`.
   Signing needs entropy, and `wc_GenerateSeed()` fails without it.
3. Open `Software Packs`, `Select Components`.
4. Enable `wolfSSL` `wolfCrypt` `Core` and `wolfCOSE` `Core`. To run the
   on device self test, also enable `wolfCOSE` `Test`.
5. In the `Software Packs` configuration category, enable each pack.
6. Generate code and build with your toolchain.

## Configure algorithms

wolfCOSE reads its configuration from the wolfSSL `user_settings.h`, included
before `wolfcose/settings.h`. Enable the wolfCrypt features that match the COSE
algorithms you use:

- ES256: `HAVE_ECC`, `WOLFSSL_SHA256`
- ES384 or ES512: add `WOLFSSL_SHA384` or `WOLFSSL_SHA512`
- ML-DSA (RFC 9964): `WOLFSSL_HAVE_MLDSA`
- Encrypt0 AEAD: `HAVE_AESGCM`, or `HAVE_CHACHA` with `HAVE_POLY1305`
- MAC0: HMAC, which is on by default with SHA support

If a required wolfCrypt feature is missing, `wolfcose/settings.h` raises a
compile error naming it.

## Run on a device

The `Test` component builds `wolfcose_test.c`, a self test that runs a
`COSE_Sign1` sign and verify and reports the result over your configured
console. Call `wolfCOSETest()` from your application once `main` has initialized
the clocks and console.

A ready to run example for the NUCLEO-H563ZI board lives in
[wolfssl-examples-stm32](https://github.com/wolfSSL/wolfssl-examples-stm32),
with a pre-configured `.ioc`: install the packs, open the `.ioc`, generate,
add the glue and software-crypto config from that example's README, build,
flash, and watch the console.

Verified on NUCLEO-H563ZI hardware, the console prints:

```
== wolfCOSE NUCLEO-H563ZI ==
Running wolfCOSE test (COSE_Sign1 ESP256)...
wolfCOSE test: PASS (COSE_Sign1 99 bytes)
```

## Notes

- Only pack source is kept in the repository. The built pack is posted at
  [wolfssl.com/files/ide/I-CUBE-wolfCOSE.pack](https://www.wolfssl.com/files/ide/I-CUBE-wolfCOSE.pack).
- On some STM32 families the wolfSSL pack enables hardware hash and RNG by
  default. If a build reports a missing HAL module or hash symbol, enable the
  matching peripheral in the `.ioc`, or select software crypto with
  `NO_STM32_HASH` and `NO_STM32_RNG` in the generated
  `wolfSSL.I-CUBE-wolfSSL_conf.h`. On the STM32H5 the hardware hash block
  references a HAL enum that does not exist, so software crypto is required
  there; the
  [NUCLEO-H563ZI example](https://github.com/wolfSSL/wolfssl-examples-stm32/tree/master/wolfCOSE-STM32-Example)
  shows the exact edit.
