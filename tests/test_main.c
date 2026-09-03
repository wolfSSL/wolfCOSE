/* test_main.c
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfCOSE.
 *
 * wolfCOSE is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfCOSE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

/**
 * wolfCOSE test harness. CI-friendly: returns 0 if all pass, 1 on failure.
 */

#include <stdio.h>

#include "test_suite.h"

int main(void)
{
    int failures = 0;

    printf("=== wolfCOSE Test Suite ===\n\n");

    printf("--- CBOR Tests (RFC 8949) ---\n");
    failures += test_cbor();

    printf("\n--- COSE Tests (RFC 9052) ---\n");
    failures += test_cose();

    printf("\n--- Interoperability Tests ---\n");
    failures += test_interop();

    printf("\n--- PSA/EAT Tests ---\n");
    failures += test_eat_psa();
    failures += test_eat_psa_profiles();

    printf("\n=== Results: %s ===\n",
           (failures == 0) ? "ALL PASSED" : "FAILURES");

    if (failures > 0) {
        printf("%d test(s) failed.\n", failures);
    }

    return (failures == 0) ? 0 : 1;
}
