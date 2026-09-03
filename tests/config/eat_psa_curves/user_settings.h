/* P-256-only wolfSSL configuration used by the PSA/EAT feature matrix. */
#ifndef WOLFCOSE_TEST_EAT_PSA_CURVES_H
#define WOLFCOSE_TEST_EAT_PSA_CURVES_H

#define HAVE_ECC
#define ECC_USER_CURVES
#define ECC_TIMING_RESISTANT
#define NO_RSA
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

#endif /* WOLFCOSE_TEST_EAT_PSA_CURVES_H */
