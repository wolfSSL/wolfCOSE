/* test_eat_psa_derived_gate.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfCOSE.
 */

/* The feature-matrix target compiles this translation unit with a partial
 * receiver and a caller-supplied WOLFCOSE_EAT_PSA_TFM_FULL. It must fail:
 * #tfm capability is derived by settings.h, never caller selectable.
 *
 * A second target combines HAVE_ALL_CURVES with an explicit NO_ECC256. The
 * explicit P-256 exclusion must win, so neither ES256 nor the complete #tfm
 * receiver capability may be derived. */
#include <wolfcose/wolfcose.h>

#if defined(WOLFCOSE_TEST_NO_ECC256_ALL_CURVES)
    #if defined(WOLFCOSE_HAVE_ES256)
        #error "NO_ECC256 must disable ES256 even with HAVE_ALL_CURVES"
    #endif
    #if defined(WOLFCOSE_EAT_PSA_TFM_FULL)
        #error "NO_ECC256 must prevent complete #tfm receiver capability"
    #endif
#endif

int test_eat_psa_derived_gate(void)
{
    return 0;
}
