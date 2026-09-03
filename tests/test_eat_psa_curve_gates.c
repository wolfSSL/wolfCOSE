/* test_eat_psa_curve_gates.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfCOSE.
 */

#include <wolfcose/wolfcose.h>

#if !defined(WOLFCOSE_EAT_PSA)
    #error "PSA/EAT feature matrix must select PSA/EAT"
#endif

#if !defined(WOLFCOSE_HAVE_ES256)
    #error "P-256-only wolfSSL configuration must retain ES256"
#endif

#if defined(WOLFCOSE_HAVE_ES384) || defined(WOLFCOSE_HAVE_ES512)
    #error "P-256-only wolfSSL configuration must not expose ES384 or ES512"
#endif

#if defined(WOLFCOSE_EAT_PSA_TFM_FULL)
    #error "P-256-only receiver must not claim RFC 9783 #tfm conformance"
#endif

int test_eat_psa_curve_gates(void)
{
    return 0;
}
