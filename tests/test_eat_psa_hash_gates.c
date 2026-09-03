/* test_eat_psa_hash_gates.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfCOSE.
 */

/* Compile this with NO_SHA256 and the current Sign1/Mac0 feature selection.
 * RFC 9783 Section 5.2 requires both ES256 and HMAC-256, so this configuration
 * must never advertise the standardized #tfm receiver profile. */
#include <wolfcose/wolfcose.h>

#if !defined(WOLFCOSE_EAT_PSA)
    #error "PSA/EAT feature matrix must select PSA/EAT"
#endif

#if defined(WOLFCOSE_HAVE_ES256)
    #error "NO_SHA256 must remove ES256 support"
#endif

#if defined(WOLFCOSE_HAVE_HMAC256)
    #error "NO_SHA256 must remove HMAC-256 support"
#endif

#if defined(WOLFCOSE_EAT_PSA_TFM_FULL)
    #error "NO_SHA256 receiver must not claim RFC 9783 #tfm conformance"
#endif

int test_eat_psa_hash_gates(void)
{
    return 0;
}
