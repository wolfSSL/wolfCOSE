/* test_suite.h
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

#ifndef WOLFCOSE_TEST_SUITE_H
#define WOLFCOSE_TEST_SUITE_H

/* Shared prototypes for the test entry points so a compatible declaration is
 * visible at each definition (MISRA C:2023 Rule 8.4). */
int test_cbor(void);
int test_cose(void);
int test_interop(void);
int test_eat_psa(void);
int test_eat_psa_profiles(void);

#endif /* WOLFCOSE_TEST_SUITE_H */
