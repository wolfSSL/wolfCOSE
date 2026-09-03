/* test_eat_psa_profile_main.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfCOSE.
 */

#include <stdio.h>

#include "test_suite.h"

int main(void)
{
    int failures;

    (void)printf("=== wolfCOSE PSA/EAT Feature Profile Tests ===\n\n");
    failures = test_eat_psa_profiles();
    (void)printf("\n=== Results: %s ===\n",
        (failures == 0) ? "ALL PASSED" : "FAILURES");

    return (failures == 0) ? 0 : 1;
}
