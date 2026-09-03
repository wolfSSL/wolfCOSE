/* SHA-384/512-capable wolfSSL configuration without SHA-256. */
#ifndef WOLFCOSE_TEST_EAT_PSA_NO_SHA256_H
#define WOLFCOSE_TEST_EAT_PSA_NO_SHA256_H

#define HAVE_ECC
#define HAVE_ALL_CURVES
#define ECC_TIMING_RESISTANT
#define NO_RSA
#define NO_SHA224
#define NO_SHA256
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
/* This is a compile-only algorithm-derivation fixture. No RNG is needed, and
 * wolfSSL 5.8.x otherwise instantiates its SHA-256 Hash-DRBG unconditionally. */
#define WC_NO_HASHDRBG
#define WC_NO_RNG

#endif /* WOLFCOSE_TEST_EAT_PSA_NO_SHA256_H */
