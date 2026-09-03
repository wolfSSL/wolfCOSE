/* test_eat_psa_min_key_gates.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfCOSE.
 */

#include <wolfcose/wolfcose.h>

#if !defined(ECC_MIN_KEY_SZ)
    #error "ECC_MIN_KEY_SZ boundary test needs an explicit minimum"
#endif

#if ECC_MIN_KEY_SZ == 256
    #if !defined(WOLFCOSE_HAVE_ES256) || !defined(WOLFCOSE_HAVE_ES384) || \
        !defined(WOLFCOSE_HAVE_ES512)
        #error "256-bit minimum must retain ES256, ES384, and ES512"
    #endif
    #if !defined(WOLFCOSE_EAT_PSA_TFM_FULL)
        #error "256-bit minimum must retain complete #tfm capability"
    #endif
#elif ECC_MIN_KEY_SZ == 257
    #if defined(WOLFCOSE_HAVE_ES256)
        #error "257-bit minimum must disable ES256"
    #endif
    #if !defined(WOLFCOSE_HAVE_ES384) || !defined(WOLFCOSE_HAVE_ES512)
        #error "257-bit minimum must retain ES384 and ES512"
    #endif
#elif ECC_MIN_KEY_SZ == 384
    #if defined(WOLFCOSE_HAVE_ES256)
        #error "384-bit minimum must disable ES256"
    #endif
    #if !defined(WOLFCOSE_HAVE_ES384) || !defined(WOLFCOSE_HAVE_ES512)
        #error "384-bit minimum must retain ES384 and ES512"
    #endif
#elif ECC_MIN_KEY_SZ == 521
    #if defined(WOLFCOSE_HAVE_ES256) || defined(WOLFCOSE_HAVE_ES384)
        #error "521-bit minimum must disable ES256 and ES384"
    #endif
    #if !defined(WOLFCOSE_HAVE_ES512)
        #error "521-bit minimum must retain ES512"
    #endif
#elif ECC_MIN_KEY_SZ == 522
    #if defined(WOLFCOSE_HAVE_ES256) || defined(WOLFCOSE_HAVE_ES384) || \
        defined(WOLFCOSE_HAVE_ES512)
        #error "minimum above P-521 must disable every ECDSA algorithm"
    #endif
#else
    #error "unexpected ECC_MIN_KEY_SZ boundary"
#endif

#if (ECC_MIN_KEY_SZ != 256) && defined(WOLFCOSE_EAT_PSA_TFM_FULL)
    #error "restricted ECC minimum must prevent complete #tfm capability"
#endif

int test_eat_psa_min_key_gates(void)
{
    return 0;
}
