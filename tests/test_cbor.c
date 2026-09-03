/* test_cbor.c
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
 * CBOR encoder/decoder tests. Covers:
 * - RFC 8949 Appendix A known vectors
 * - Round-trip encode/decode for all types
 * - Nested structures (arrays of maps, maps of arrays)
 * - wc_CBOR_Skip over complex items
 * - Error cases: buffer overflow, truncated input, wrong type, depth limit
 * - Edge cases: empty bstr/tstr, zero-length array/map
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfcose/wolfcose.h>
#include <stdio.h>
#include <string.h>

#include "test_suite.h"

static int g_failures = 0;

#define TEST_ASSERT(cond, name) do {                           \
    if (!(cond)) {                                             \
        printf("  FAIL: %s (line %d)\n", (name), __LINE__);   \
        g_failures++;                                          \
    } else {                                                   \
        printf("  PASS: %s\n", (name));                        \
    }                                                          \
} while (0)

#define TEST_ASSERT_EQ(a, b, name) TEST_ASSERT((a) == (b), (name))

/* Helper: encode then compare output bytes to expected hex */
static int check_encode_hex(const uint8_t* buf, size_t len,
                             const uint8_t* expected, size_t expectedLen)
{
    if (len != expectedLen) {
        return 0;
    }
    return (memcmp(buf, expected, len) == 0) ? 1 : 0;
}

/* ----- RFC 8949 Appendix A: Known encode vectors ----- */
static void test_cbor_encode_vectors(void)
{
    uint8_t buf[64];
    WOLFCOSE_CBOR_CTX ctx;
    int ret;

    printf("  [Encode Vectors]\n");

    /* 0 -> 0x00 */
    ctx.buf = buf; ctx.bufSz = sizeof(buf); ctx.idx = 0;
    ret = wc_CBOR_EncodeUint(&ctx, 0);
    TEST_ASSERT(ret == 0 && ctx.idx == 1 && buf[0] == 0x00,
                "uint 0");

    /* 23 -> 0x17 */
    ctx.idx = 0;
    ret = wc_CBOR_EncodeUint(&ctx, 23);
    TEST_ASSERT(ret == 0 && ctx.idx == 1 && buf[0] == 0x17,
                "uint 23");

    /* 24 -> 0x18 0x18 */
    ctx.idx = 0;
    ret = wc_CBOR_EncodeUint(&ctx, 24);
    { const uint8_t exp[] = {0x18, 0x18};
      TEST_ASSERT(ret == 0 && check_encode_hex(buf, ctx.idx, exp, 2),
                  "uint 24"); }

    /* 100 -> 0x18 0x64 */
    ctx.idx = 0;
    ret = wc_CBOR_EncodeUint(&ctx, 100);
    { const uint8_t exp[] = {0x18, 0x64};
      TEST_ASSERT(ret == 0 && check_encode_hex(buf, ctx.idx, exp, 2),
                  "uint 100"); }

    /* 1000 -> 0x19 0x03 0xE8 */
    ctx.idx = 0;
    ret = wc_CBOR_EncodeUint(&ctx, 1000);
    { const uint8_t exp[] = {0x19, 0x03, 0xE8};
      TEST_ASSERT(ret == 0 && check_encode_hex(buf, ctx.idx, exp, 3),
                  "uint 1000"); }

    /* 1000000 -> 0x1A 0x00 0x0F 0x42 0x40 */
    ctx.idx = 0;
    ret = wc_CBOR_EncodeUint(&ctx, 1000000);
    { const uint8_t exp[] = {0x1A, 0x00, 0x0F, 0x42, 0x40};
      TEST_ASSERT(ret == 0 && check_encode_hex(buf, ctx.idx, exp, 5),
                  "uint 1000000"); }

    /* 1000000000000 -> 9 bytes */
    ctx.idx = 0;
    ret = wc_CBOR_EncodeUint(&ctx, 1000000000000ULL);
    { const uint8_t exp[] = {0x1B, 0x00, 0x00, 0x00, 0xE8, 0xD4, 0xA5, 0x10, 0x00};
      TEST_ASSERT(ret == 0 && check_encode_hex(buf, ctx.idx, exp, 9),
                  "uint 1000000000000"); }

    /* -1 -> 0x20 */
    ctx.idx = 0;
    ret = wc_CBOR_EncodeInt(&ctx, -1);
    TEST_ASSERT(ret == 0 && ctx.idx == 1 && buf[0] == 0x20,
                "int -1");

    /* -100 -> 0x38 0x63 */
    ctx.idx = 0;
    ret = wc_CBOR_EncodeInt(&ctx, -100);
    { const uint8_t exp[] = {0x38, 0x63};
      TEST_ASSERT(ret == 0 && check_encode_hex(buf, ctx.idx, exp, 2),
                  "int -100"); }

    /* -1000 -> 0x39 0x03 0xE7 */
    ctx.idx = 0;
    ret = wc_CBOR_EncodeInt(&ctx, -1000);
    { const uint8_t exp[] = {0x39, 0x03, 0xE7};
      TEST_ASSERT(ret == 0 && check_encode_hex(buf, ctx.idx, exp, 3),
                  "int -1000"); }

    /* empty bstr h'' -> 0x40 */
    ctx.idx = 0;
    ret = wc_CBOR_EncodeBstr(&ctx, NULL, 0);
    TEST_ASSERT(ret == 0 && ctx.idx == 1 && buf[0] == 0x40,
                "bstr empty");

    /* bstr h'01020304' -> 0x44 0x01 0x02 0x03 0x04 */
    ctx.idx = 0;
    { const uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
      const uint8_t exp[] = {0x44, 0x01, 0x02, 0x03, 0x04};
      ret = wc_CBOR_EncodeBstr(&ctx, data, 4);
      TEST_ASSERT(ret == 0 && check_encode_hex(buf, ctx.idx, exp, 5),
                  "bstr 4 bytes"); }

    /* empty tstr "" -> 0x60 */
    ctx.idx = 0;
    ret = wc_CBOR_EncodeTstr(&ctx, NULL, 0);
    TEST_ASSERT(ret == 0 && ctx.idx == 1 && buf[0] == 0x60,
                "tstr empty");

    /* tstr "IETF" -> 0x64 0x49 0x45 0x54 0x46 */
    ctx.idx = 0;
    ret = wc_CBOR_EncodeTstr(&ctx, (const uint8_t*)"IETF", 4);
    { const uint8_t exp[] = {0x64, 0x49, 0x45, 0x54, 0x46};
      TEST_ASSERT(ret == 0 && check_encode_hex(buf, ctx.idx, exp, 5),
                  "tstr IETF"); }

    /* empty array [] -> 0x80 */
    ctx.idx = 0;
    ret = wc_CBOR_EncodeArrayStart(&ctx, 0);
    TEST_ASSERT(ret == 0 && ctx.idx == 1 && buf[0] == 0x80,
                "array empty");

    /* [1, 2, 3] -> 0x83 0x01 0x02 0x03 */
    ctx.idx = 0;
    ret = wc_CBOR_EncodeArrayStart(&ctx, 3);
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&ctx, 1);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&ctx, 2);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&ctx, 3);
    }
    { const uint8_t exp[] = {0x83, 0x01, 0x02, 0x03};
      TEST_ASSERT(ret == 0 && check_encode_hex(buf, ctx.idx, exp, 4),
                  "array [1,2,3]"); }

    /* empty map {} -> 0xA0 */
    ctx.idx = 0;
    ret = wc_CBOR_EncodeMapStart(&ctx, 0);
    TEST_ASSERT(ret == 0 && ctx.idx == 1 && buf[0] == 0xA0,
                "map empty");

    /* false -> 0xF4 */
    ctx.idx = 0;
    ret = wc_CBOR_EncodeFalse(&ctx);
    TEST_ASSERT(ret == 0 && ctx.idx == 1 && buf[0] == 0xF4,
                "false");

    /* true -> 0xF5 */
    ctx.idx = 0;
    ret = wc_CBOR_EncodeTrue(&ctx);
    TEST_ASSERT(ret == 0 && ctx.idx == 1 && buf[0] == 0xF5,
                "true");

    /* null -> 0xF6 */
    ctx.idx = 0;
    ret = wc_CBOR_EncodeNull(&ctx);
    TEST_ASSERT(ret == 0 && ctx.idx == 1 && buf[0] == 0xF6,
                "null");

    /* Tag(1) -> 0xC1 */
    ctx.idx = 0;
    ret = wc_CBOR_EncodeTag(&ctx, 1);
    TEST_ASSERT(ret == 0 && ctx.idx == 1 && buf[0] == 0xC1,
                "tag 1");
}

/* ----- Decode known vectors ----- */
static void test_cbor_decode_vectors(void)
{
    WOLFCOSE_CBOR_CTX ctx;
    int ret;
    uint64_t uval;
    int64_t ival;
    const uint8_t* data;
    size_t dataLen;
    size_t count;
    uint64_t tag;

    printf("  [Decode Vectors]\n");

    /* uint 0 */
    { uint8_t in[] = {0x00};
      ctx.cbuf = in; ctx.bufSz = sizeof(in); ctx.idx = 0;
      ret = wc_CBOR_DecodeUint(&ctx, &uval);
      TEST_ASSERT(ret == 0 && uval == 0, "decode uint 0"); }

    /* uint 23 */
    { uint8_t in[] = {0x17};
      ctx.cbuf = in; ctx.bufSz = sizeof(in); ctx.idx = 0;
      ret = wc_CBOR_DecodeUint(&ctx, &uval);
      TEST_ASSERT(ret == 0 && uval == 23, "decode uint 23"); }

    /* uint 24 */
    { uint8_t in[] = {0x18, 0x18};
      ctx.cbuf = in; ctx.bufSz = sizeof(in); ctx.idx = 0;
      ret = wc_CBOR_DecodeUint(&ctx, &uval);
      TEST_ASSERT(ret == 0 && uval == 24, "decode uint 24"); }

    /* uint 100 */
    { uint8_t in[] = {0x18, 0x64};
      ctx.cbuf = in; ctx.bufSz = sizeof(in); ctx.idx = 0;
      ret = wc_CBOR_DecodeUint(&ctx, &uval);
      TEST_ASSERT(ret == 0 && uval == 100, "decode uint 100"); }

    /* uint 1000 */
    { uint8_t in[] = {0x19, 0x03, 0xE8};
      ctx.cbuf = in; ctx.bufSz = sizeof(in); ctx.idx = 0;
      ret = wc_CBOR_DecodeUint(&ctx, &uval);
      TEST_ASSERT(ret == 0 && uval == 1000, "decode uint 1000"); }

    /* uint 1000000 */
    { uint8_t in[] = {0x1A, 0x00, 0x0F, 0x42, 0x40};
      ctx.cbuf = in; ctx.bufSz = sizeof(in); ctx.idx = 0;
      ret = wc_CBOR_DecodeUint(&ctx, &uval);
      TEST_ASSERT(ret == 0 && uval == 1000000, "decode uint 1000000"); }

    /* uint 1000000000000 */
    { uint8_t in[] = {0x1B, 0x00, 0x00, 0x00, 0xE8, 0xD4, 0xA5, 0x10, 0x00};
      ctx.cbuf = in; ctx.bufSz = sizeof(in); ctx.idx = 0;
      ret = wc_CBOR_DecodeUint(&ctx, &uval);
      TEST_ASSERT(ret == 0 && uval == 1000000000000ULL,
                  "decode uint 1000000000000"); }

    /* int -1 */
    { uint8_t in[] = {0x20};
      ctx.cbuf = in; ctx.bufSz = sizeof(in); ctx.idx = 0;
      ret = wc_CBOR_DecodeInt(&ctx, &ival);
      TEST_ASSERT(ret == 0 && ival == -1, "decode int -1"); }

    /* int -100 */
    { uint8_t in[] = {0x38, 0x63};
      ctx.cbuf = in; ctx.bufSz = sizeof(in); ctx.idx = 0;
      ret = wc_CBOR_DecodeInt(&ctx, &ival);
      TEST_ASSERT(ret == 0 && ival == -100, "decode int -100"); }

    /* int -1000 */
    { uint8_t in[] = {0x39, 0x03, 0xE7};
      ctx.cbuf = in; ctx.bufSz = sizeof(in); ctx.idx = 0;
      ret = wc_CBOR_DecodeInt(&ctx, &ival);
      TEST_ASSERT(ret == 0 && ival == -1000, "decode int -1000"); }

    /* Positive int via DecodeInt */
    { uint8_t in[] = {0x18, 0x64};
      ctx.cbuf = in; ctx.bufSz = sizeof(in); ctx.idx = 0;
      ret = wc_CBOR_DecodeInt(&ctx, &ival);
      TEST_ASSERT(ret == 0 && ival == 100, "decode int +100"); }

    /* Boundary: unsigned INT64_MAX (0x1B 7F FF ...) decodes exactly. */
    { uint8_t in[] = {0x1B, 0x7F, 0xFF, 0xFF, 0xFF,
                      0xFF, 0xFF, 0xFF, 0xFF};
      ctx.cbuf = in; ctx.bufSz = sizeof(in); ctx.idx = 0;
      ret = wc_CBOR_DecodeInt(&ctx, &ival);
      TEST_ASSERT(ret == 0 && ival == INT64_MAX, "decode INT64_MAX"); }

    /* Boundary: negint -1 - INT64_MAX == INT64_MIN. */
    { uint8_t in[] = {0x3B, 0x7F, 0xFF, 0xFF, 0xFF,
                      0xFF, 0xFF, 0xFF, 0xFF};
      ctx.cbuf = in; ctx.bufSz = sizeof(in); ctx.idx = 0;
      ret = wc_CBOR_DecodeInt(&ctx, &ival);
      TEST_ASSERT(ret == 0 && ival == INT64_MIN, "decode INT64_MIN"); }

    /* bstr empty */
    { uint8_t in[] = {0x40};
      ctx.cbuf = in; ctx.bufSz = sizeof(in); ctx.idx = 0;
      ret = wc_CBOR_DecodeBstr(&ctx, &data, &dataLen);
      TEST_ASSERT(ret == 0 && dataLen == 0, "decode bstr empty"); }

    /* bstr 4 bytes */
    { uint8_t in[] = {0x44, 0x01, 0x02, 0x03, 0x04};
      ctx.cbuf = in; ctx.bufSz = sizeof(in); ctx.idx = 0;
      ret = wc_CBOR_DecodeBstr(&ctx, &data, &dataLen);
      TEST_ASSERT(ret == 0 && dataLen == 4 && data[0] == 0x01 &&
                  data[3] == 0x04, "decode bstr 4 bytes"); }

    /* tstr empty */
    { uint8_t in[] = {0x60};
      ctx.cbuf = in; ctx.bufSz = sizeof(in); ctx.idx = 0;
      ret = wc_CBOR_DecodeTstr(&ctx, &data, &dataLen);
      TEST_ASSERT(ret == 0 && dataLen == 0, "decode tstr empty"); }

    /* tstr "IETF" */
    { uint8_t in[] = {0x64, 0x49, 0x45, 0x54, 0x46};
      ctx.cbuf = in; ctx.bufSz = sizeof(in); ctx.idx = 0;
      ret = wc_CBOR_DecodeTstr(&ctx, &data, &dataLen);
      TEST_ASSERT(ret == 0 && dataLen == 4 &&
                  memcmp(data, "IETF", 4) == 0, "decode tstr IETF"); }

    /* array [1, 2, 3] */
    { uint8_t in[] = {0x83, 0x01, 0x02, 0x03};
      ctx.cbuf = in; ctx.bufSz = sizeof(in); ctx.idx = 0;
      ret = wc_CBOR_DecodeArrayStart(&ctx, &count);
      TEST_ASSERT(ret == 0 && count == 3, "decode array start 3");
      if (ret == 0) {
          ret = wc_CBOR_DecodeUint(&ctx, &uval);
          TEST_ASSERT(ret == 0 && uval == 1, "decode array[0]=1");
          ret = wc_CBOR_DecodeUint(&ctx, &uval);
          TEST_ASSERT(ret == 0 && uval == 2, "decode array[1]=2");
          ret = wc_CBOR_DecodeUint(&ctx, &uval);
          TEST_ASSERT(ret == 0 && uval == 3, "decode array[2]=3");
      } }

    /* empty map */
    { uint8_t in[] = {0xA0};
      ctx.cbuf = in; ctx.bufSz = sizeof(in); ctx.idx = 0;
      ret = wc_CBOR_DecodeMapStart(&ctx, &count);
      TEST_ASSERT(ret == 0 && count == 0, "decode map empty"); }

    /* Tag(18) */
    { uint8_t in[] = {0xD2};
      ctx.cbuf = in; ctx.bufSz = sizeof(in); ctx.idx = 0;
      ret = wc_CBOR_DecodeTag(&ctx, &tag);
      TEST_ASSERT(ret == 0 && tag == 18, "decode tag 18"); }

    /* false, true, null via DecodeHead */
    { uint8_t in[] = {0xF4};
      WOLFCOSE_CBOR_ITEM item;
      ctx.cbuf = in; ctx.bufSz = sizeof(in); ctx.idx = 0;
      ret = wc_CBOR_DecodeHead(&ctx, &item);
      TEST_ASSERT(ret == 0 && item.majorType == WOLFCOSE_CBOR_SIMPLE &&
                  item.val == 20, "decode false"); }

    { uint8_t in[] = {0xF5};
      WOLFCOSE_CBOR_ITEM item;
      ctx.cbuf = in; ctx.bufSz = sizeof(in); ctx.idx = 0;
      ret = wc_CBOR_DecodeHead(&ctx, &item);
      TEST_ASSERT(ret == 0 && item.majorType == WOLFCOSE_CBOR_SIMPLE &&
                  item.val == 21, "decode true"); }

    { uint8_t in[] = {0xF6};
      WOLFCOSE_CBOR_ITEM item;
      ctx.cbuf = in; ctx.bufSz = sizeof(in); ctx.idx = 0;
      ret = wc_CBOR_DecodeHead(&ctx, &item);
      TEST_ASSERT(ret == 0 && item.majorType == WOLFCOSE_CBOR_SIMPLE &&
                  item.val == 22, "decode null"); }
}

/* ----- Round-trip encode -> decode ----- */
static void test_cbor_roundtrip(void)
{
    uint8_t buf[256];
    WOLFCOSE_CBOR_CTX enc, dec;
    int ret;
    uint64_t uval;
    int64_t ival;
    const uint8_t* data;
    size_t dataLen;
    size_t count;
    uint64_t tag;

    printf("  [Round-trip]\n");

    /* Encode a complex structure: Tag(99) [42, -7, h'DEADBEEF', "hello", {}] */
    enc.buf = buf; enc.bufSz = sizeof(buf); enc.idx = 0;
    ret = wc_CBOR_EncodeTag(&enc, 99);
    if (ret == 0) {
        ret = wc_CBOR_EncodeArrayStart(&enc, 5);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&enc, 42);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeInt(&enc, -7);
    }
    if (ret == 0) {
        const uint8_t bdata[] = {0xDE, 0xAD, 0xBE, 0xEF};
        ret = wc_CBOR_EncodeBstr(&enc, bdata, 4);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeTstr(&enc, (const uint8_t*)"hello", 5);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeMapStart(&enc, 0);
    }
    TEST_ASSERT(ret == 0, "rt encode complex");

    /* Decode it back */
    dec.cbuf = buf; dec.bufSz = enc.idx; dec.idx = 0;
    ret = wc_CBOR_DecodeTag(&dec, &tag);
    TEST_ASSERT(ret == 0 && tag == 99, "rt tag");

    ret = wc_CBOR_DecodeArrayStart(&dec, &count);
    TEST_ASSERT(ret == 0 && count == 5, "rt array 5");

    ret = wc_CBOR_DecodeUint(&dec, &uval);
    TEST_ASSERT(ret == 0 && uval == 42, "rt uint 42");

    ret = wc_CBOR_DecodeInt(&dec, &ival);
    TEST_ASSERT(ret == 0 && ival == -7, "rt int -7");

    ret = wc_CBOR_DecodeBstr(&dec, &data, &dataLen);
    TEST_ASSERT(ret == 0 && dataLen == 4 && data[0] == 0xDE,
                "rt bstr");

    ret = wc_CBOR_DecodeTstr(&dec, &data, &dataLen);
    TEST_ASSERT(ret == 0 && dataLen == 5 && memcmp(data, "hello", 5) == 0,
                "rt tstr");

    ret = wc_CBOR_DecodeMapStart(&dec, &count);
    TEST_ASSERT(ret == 0 && count == 0, "rt map empty");

    TEST_ASSERT(dec.idx == enc.idx, "rt consumed all bytes");
}

/* ----- Nested structures ----- */
static void test_cbor_nested(void)
{
    uint8_t buf[128];
    WOLFCOSE_CBOR_CTX enc, dec;
    int ret;
    size_t count;
    uint64_t uval;
    const uint8_t* data;
    size_t dataLen;

    printf("  [Nested structures]\n");

    /* {1: [10, 20], 2: "abc"} */
    enc.buf = buf; enc.bufSz = sizeof(buf); enc.idx = 0;
    ret = wc_CBOR_EncodeMapStart(&enc, 2);
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&enc, 1);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeArrayStart(&enc, 2);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&enc, 10);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&enc, 20);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&enc, 2);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeTstr(&enc, (const uint8_t*)"abc", 3);
    }
    TEST_ASSERT(ret == 0, "nested encode");

    /* Decode it */
    dec.cbuf = buf; dec.bufSz = enc.idx; dec.idx = 0;
    ret = wc_CBOR_DecodeMapStart(&dec, &count);
    TEST_ASSERT(ret == 0 && count == 2, "nested map 2");

    ret = wc_CBOR_DecodeUint(&dec, &uval);
    TEST_ASSERT(ret == 0 && uval == 1, "nested key 1");

    ret = wc_CBOR_DecodeArrayStart(&dec, &count);
    TEST_ASSERT(ret == 0 && count == 2, "nested inner array");

    ret = wc_CBOR_DecodeUint(&dec, &uval);
    TEST_ASSERT(ret == 0 && uval == 10, "nested arr[0]");
    ret = wc_CBOR_DecodeUint(&dec, &uval);
    TEST_ASSERT(ret == 0 && uval == 20, "nested arr[1]");

    ret = wc_CBOR_DecodeUint(&dec, &uval);
    TEST_ASSERT(ret == 0 && uval == 2, "nested key 2");

    ret = wc_CBOR_DecodeTstr(&dec, &data, &dataLen);
    TEST_ASSERT(ret == 0 && dataLen == 3 && memcmp(data, "abc", 3) == 0,
                "nested tstr");
}

/* ----- wc_CBOR_Skip ----- */
static void test_cbor_skip(void)
{
    uint8_t buf[128];
    WOLFCOSE_CBOR_CTX enc, dec;
    int ret;
    uint64_t uval;

    printf("  [Skip]\n");

    /* Encode: [42, {1: "foo", 2: [10, 20, 30]}, 99]
     * Skip the middle map, then read 99 */
    enc.buf = buf; enc.bufSz = sizeof(buf); enc.idx = 0;
    ret = wc_CBOR_EncodeArrayStart(&enc, 3);
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&enc, 42);
    }
    /* map {1: "foo", 2: [10, 20, 30]} */
    if (ret == 0) {
        ret = wc_CBOR_EncodeMapStart(&enc, 2);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&enc, 1);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeTstr(&enc, (const uint8_t*)"foo", 3);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&enc, 2);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeArrayStart(&enc, 3);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&enc, 10);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&enc, 20);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&enc, 30);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&enc, 99);
    }
    TEST_ASSERT(ret == 0, "skip encode");

    dec.cbuf = buf; dec.bufSz = enc.idx; dec.idx = 0;
    { size_t count;
      ret = wc_CBOR_DecodeArrayStart(&dec, &count);
      TEST_ASSERT(ret == 0 && count == 3, "skip array start"); }

    ret = wc_CBOR_DecodeUint(&dec, &uval);
    TEST_ASSERT(ret == 0 && uval == 42, "skip read 42");

    /* Skip the entire map */
    ret = wc_CBOR_Skip(&dec);
    TEST_ASSERT(ret == 0, "skip map");

    /* Now read 99 */
    ret = wc_CBOR_DecodeUint(&dec, &uval);
    TEST_ASSERT(ret == 0 && uval == 99, "skip read 99 after");

    /* Skip over tagged item: Tag(18) h'AA' */
    enc.idx = 0;
    ret = wc_CBOR_EncodeTag(&enc, 18);
    if (ret == 0) {
        uint8_t b = 0xAA;
        ret = wc_CBOR_EncodeBstr(&enc, &b, 1);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&enc, 77);
    }
    TEST_ASSERT(ret == 0, "skip tagged encode");

    dec.cbuf = buf; dec.bufSz = enc.idx; dec.idx = 0;
    ret = wc_CBOR_Skip(&dec);
    TEST_ASSERT(ret == 0, "skip tagged item");

    ret = wc_CBOR_DecodeUint(&dec, &uval);
    TEST_ASSERT(ret == 0 && uval == 77, "skip read after tagged");
}

static void test_cbor_skip_depth(void)
{
    /* Construct a CBOR value with array nesting deeper than
     * WOLFCOSE_CBOR_MAX_DEPTH (8). wc_CBOR_Skip must reject it instead
     * of overflowing its stack-local depth tracker. */
    uint8_t deep[12];
    WOLFCOSE_CBOR_CTX dec;
    size_t i;
    int ret;

    printf("  [Skip: depth limit]\n");
    for (i = 0; i < sizeof(deep); i++) {
        deep[i] = 0x81u; /* array(1) */
    }

    dec.cbuf = deep;
    dec.bufSz = sizeof(deep);
    dec.idx = 0;
    ret = wc_CBOR_Skip(&dec);
    TEST_ASSERT(ret == WOLFCOSE_E_CBOR_DEPTH,
                "wc_CBOR_Skip rejects deeply nested CBOR");
}

static void test_cbor_skip_tainted_count(void)
{
    /* Array header claiming more items than the buffer can possibly
     * hold must be rejected by wc_CBOR_Skip. Use AI=27 (8-byte arg)
     * with value 0xFFFFFFFFFFFFFFFF to exercise both the
     * `val > bufSz` and `val > SIZE_MAX/2` sanity gates. */
    uint8_t tainted[10];
    WOLFCOSE_CBOR_CTX dec;
    int ret;

    printf("  [Skip: tainted item count]\n");
    tainted[0] = 0x9Bu; /* array(8-byte) */
    tainted[1] = 0xFFu;
    tainted[2] = 0xFFu;
    tainted[3] = 0xFFu;
    tainted[4] = 0xFFu;
    tainted[5] = 0xFFu;
    tainted[6] = 0xFFu;
    tainted[7] = 0xFFu;
    tainted[8] = 0xFFu;
    tainted[9] = 0x00u;

    dec.cbuf = tainted;
    dec.bufSz = sizeof(tainted);
    dec.idx = 0;
    ret = wc_CBOR_Skip(&dec);
    TEST_ASSERT(ret == WOLFCOSE_E_CBOR_MALFORMED,
                "wc_CBOR_Skip rejects tainted item count");
}

static void test_cbor_decode_simple_not_well_formed(void)
{
    /* RFC 8949 Section 3.3: two-byte 0xF8 simple value with arg < 32 is
     * not well-formed. */
    uint8_t badSimple[2];
    WOLFCOSE_CBOR_CTX dec;
    WOLFCOSE_CBOR_ITEM item;
    int ret;

    printf("  [Decode: not-well-formed simple value]\n");
    badSimple[0] = 0xF8u;
    badSimple[1] = 0x10u; /* value 16, < 32 */

    dec.cbuf = badSimple;
    dec.bufSz = sizeof(badSimple);
    dec.idx = 0;
    ret = wc_CBOR_DecodeHead(&dec, &item);
    TEST_ASSERT(ret == WOLFCOSE_E_CBOR_MALFORMED,
                "DecodeHead rejects 0xF8 simple value < 32");
}

static void test_cbor_encode_bstr_null_with_len(void)
{
    /* EncodeBstr with NULL data and non-zero length must reject the
     * call instead of emitting uninitialised buffer contents. */
    uint8_t out[32];
    WOLFCOSE_CBOR_CTX enc;
    int ret;

    printf("  [Encode: NULL bstr with non-zero length]\n");
    enc.buf = out;
    enc.bufSz = sizeof(out);
    enc.idx = 0;
    ret = wc_CBOR_EncodeBstr(&enc, NULL, 4);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG,
                "EncodeBstr rejects NULL data with positive length");
}

static void test_cbor_encode_idx_past_bufsz(void)
{
    /* WOLFCOSE_CBOR_CTX is public; a corrupted idx near SIZE_MAX must not
     * wrap the capacity check and write out of bounds. */
    uint8_t out[8];
    WOLFCOSE_CBOR_CTX enc;
    int ret;

    printf("  [Encode: idx past bufSz does not wrap]\n");
    enc.buf = out;
    enc.bufSz = sizeof(out);
    enc.idx = SIZE_MAX;
    ret = wc_CBOR_EncodeUint(&enc, 1u);
    TEST_ASSERT(ret == WOLFCOSE_E_BUFFER_TOO_SMALL,
                "EncodeUint rejects idx past bufSz");

    enc.idx = SIZE_MAX;
    ret = wc_CBOR_EncodeNull(&enc);
    TEST_ASSERT(ret == WOLFCOSE_E_BUFFER_TOO_SMALL,
                "EncodeNull rejects idx past bufSz");
}

static void test_cbor_reject_non_preferred(void)
{
    /* RFC 8949 4.2.1: arguments must use the shortest form. Overlong encodings
     * of small values must be rejected (F-5374). */
    WOLFCOSE_CBOR_CTX ctx;
    uint64_t uval;
    const uint8_t* data;
    size_t dataLen;
    size_t count;
    int ret;
    /* uint 0 encoded in 1 extra byte, uint 23 in 2, uint 255 in 4, etc. */
    uint8_t u1[]  = {0x18, 0x00};                      /* uint 0  overlong */
    uint8_t u2[]  = {0x19, 0x00, 0x17};                /* uint 23 overlong */
    uint8_t u4[]  = {0x1A, 0x00, 0x00, 0x00, 0x18};    /* uint 24 overlong */
    uint8_t u8[]  = {0x1B, 0,0,0,0, 0,0,0x01,0x00};    /* uint 256 overlong */
    uint8_t u1Max[] = {0x18, 0x17};                     /* uint 23 overlong */
    uint8_t u2Max[] = {0x19, 0x00, 0xFF};               /* uint 255 overlong */
    uint8_t u4Max[] = {0x1A, 0x00, 0x00, 0xFF, 0xFF}; /* uint 65535 overlong */
    uint8_t u8Max[] = {0x1B, 0,0,0,0, 0xFF,0xFF,0xFF,0xFF};
    uint8_t bs[]  = {0x58, 0x00};                      /* empty bstr overlong */
    uint8_t arr[] = {0x98, 0x00};                      /* array(0) overlong */

    printf("  [Decode: reject non-preferred encodings]\n");

    ctx.cbuf = u1; ctx.bufSz = sizeof(u1); ctx.idx = 0;
    ret = wc_CBOR_DecodeUint(&ctx, &uval);
    TEST_ASSERT(ret == WOLFCOSE_E_CBOR_MALFORMED, "reject overlong uint 0");

    ctx.cbuf = u2; ctx.bufSz = sizeof(u2); ctx.idx = 0;
    ret = wc_CBOR_DecodeUint(&ctx, &uval);
    TEST_ASSERT(ret == WOLFCOSE_E_CBOR_MALFORMED, "reject overlong uint 23");

    ctx.cbuf = u4; ctx.bufSz = sizeof(u4); ctx.idx = 0;
    ret = wc_CBOR_DecodeUint(&ctx, &uval);
    TEST_ASSERT(ret == WOLFCOSE_E_CBOR_MALFORMED, "reject overlong uint 24");

    ctx.cbuf = u8; ctx.bufSz = sizeof(u8); ctx.idx = 0;
    ret = wc_CBOR_DecodeUint(&ctx, &uval);
    TEST_ASSERT(ret == WOLFCOSE_E_CBOR_MALFORMED, "reject overlong uint 256");

    ctx.cbuf = u1Max; ctx.bufSz = sizeof(u1Max); ctx.idx = 0;
    ret = wc_CBOR_DecodeUint(&ctx, &uval);
    TEST_ASSERT(ret == WOLFCOSE_E_CBOR_MALFORMED,
                "reject max overlong 1-byte uint");

    ctx.cbuf = u2Max; ctx.bufSz = sizeof(u2Max); ctx.idx = 0;
    ret = wc_CBOR_DecodeUint(&ctx, &uval);
    TEST_ASSERT(ret == WOLFCOSE_E_CBOR_MALFORMED,
                "reject max overlong 2-byte uint");

    ctx.cbuf = u4Max; ctx.bufSz = sizeof(u4Max); ctx.idx = 0;
    ret = wc_CBOR_DecodeUint(&ctx, &uval);
    TEST_ASSERT(ret == WOLFCOSE_E_CBOR_MALFORMED,
                "reject max overlong 4-byte uint");

    ctx.cbuf = u8Max; ctx.bufSz = sizeof(u8Max); ctx.idx = 0;
    ret = wc_CBOR_DecodeUint(&ctx, &uval);
    TEST_ASSERT(ret == WOLFCOSE_E_CBOR_MALFORMED,
                "reject max overlong 8-byte uint");

    ctx.cbuf = bs; ctx.bufSz = sizeof(bs); ctx.idx = 0;
    ret = wc_CBOR_DecodeBstr(&ctx, &data, &dataLen);
    TEST_ASSERT(ret == WOLFCOSE_E_CBOR_MALFORMED, "reject overlong bstr len");

    ctx.cbuf = arr; ctx.bufSz = sizeof(arr); ctx.idx = 0;
    ret = wc_CBOR_DecodeArrayStart(&ctx, &count);
    TEST_ASSERT(ret == WOLFCOSE_E_CBOR_MALFORMED, "reject overlong array len");
}

/* ----- Error cases ----- */
static void test_cbor_errors(void)
{
    uint8_t buf[8];
    WOLFCOSE_CBOR_CTX ctx;
    int ret;
    uint64_t uval;
    const uint8_t* data;
    size_t dataLen;
    size_t count;
    WOLFCOSE_CBOR_ITEM item;

    printf("  [Error cases]\n");

    /* NULL ctx */
    ret = wc_CBOR_EncodeUint(NULL, 0);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "encode null ctx");

    ret = wc_CBOR_DecodeUint(NULL, &uval);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "decode null ctx");

    /* NULL output param */
    ctx.cbuf = buf; ctx.bufSz = sizeof(buf); ctx.idx = 0;
    buf[0] = 0x00;
    ret = wc_CBOR_DecodeUint(&ctx, NULL);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "decode null val");

    /* Buffer too small for encode */
    ctx.buf = buf; ctx.bufSz = 1; ctx.idx = 0;
    ret = wc_CBOR_EncodeUint(&ctx, 1000); /* needs 3 bytes */
    TEST_ASSERT(ret == WOLFCOSE_E_BUFFER_TOO_SMALL, "encode overflow");

    /* Buffer too small for bstr data */
    ctx.buf = buf; ctx.bufSz = 3; ctx.idx = 0;
    { const uint8_t d[] = {1, 2, 3, 4};
      ret = wc_CBOR_EncodeBstr(&ctx, d, 4); /* head=1 + data=4 > 3 */
      TEST_ASSERT(ret == WOLFCOSE_E_BUFFER_TOO_SMALL, "encode bstr overflow"); }

    /* Truncated input on decode */
    { uint8_t in[] = {0x19}; /* needs 2 more bytes */
      ctx.cbuf = in; ctx.bufSz = 1; ctx.idx = 0;
      ret = wc_CBOR_DecodeUint(&ctx, &uval);
      TEST_ASSERT(ret == WOLFCOSE_E_CBOR_MALFORMED, "decode truncated"); }

    /* Wrong type: expect uint, get bstr */
    { uint8_t in[] = {0x40};
      ctx.cbuf = in; ctx.bufSz = 1; ctx.idx = 0;
      ret = wc_CBOR_DecodeUint(&ctx, &uval);
      TEST_ASSERT(ret == WOLFCOSE_E_CBOR_TYPE, "decode wrong type uint"); }

    /* Wrong type: expect bstr, get uint */
    { uint8_t in[] = {0x00};
      ctx.cbuf = in; ctx.bufSz = 1; ctx.idx = 0;
      ret = wc_CBOR_DecodeBstr(&ctx, &data, &dataLen);
      TEST_ASSERT(ret == WOLFCOSE_E_CBOR_TYPE, "decode wrong type bstr"); }

    /* Wrong type: expect tstr, get uint */
    { uint8_t in[] = {0x00};
      ctx.cbuf = in; ctx.bufSz = 1; ctx.idx = 0;
      ret = wc_CBOR_DecodeTstr(&ctx, &data, &dataLen);
      TEST_ASSERT(ret == WOLFCOSE_E_CBOR_TYPE, "decode wrong type tstr"); }

    /* Wrong type: expect array, get uint */
    { uint8_t in[] = {0x00};
      ctx.cbuf = in; ctx.bufSz = 1; ctx.idx = 0;
      ret = wc_CBOR_DecodeArrayStart(&ctx, &count);
      TEST_ASSERT(ret == WOLFCOSE_E_CBOR_TYPE, "decode wrong type array"); }

    /* Wrong type: expect map, get uint */
    { uint8_t in[] = {0x00};
      ctx.cbuf = in; ctx.bufSz = 1; ctx.idx = 0;
      ret = wc_CBOR_DecodeMapStart(&ctx, &count);
      TEST_ASSERT(ret == WOLFCOSE_E_CBOR_TYPE, "decode wrong type map"); }

    /* Wrong type: expect tag, get uint */
    { uint64_t tag;
      uint8_t in[] = {0x00};
      ctx.cbuf = in; ctx.bufSz = 1; ctx.idx = 0;
      ret = wc_CBOR_DecodeTag(&ctx, &tag);
      TEST_ASSERT(ret == WOLFCOSE_E_CBOR_TYPE, "decode wrong type tag"); }

    /* Indefinite length -> unsupported */
    { uint8_t in[] = {0x5F}; /* bstr indefinite */
      ctx.cbuf = in; ctx.bufSz = 1; ctx.idx = 0;
      ret = wc_CBOR_DecodeHead(&ctx, &item);
      TEST_ASSERT(ret == WOLFCOSE_E_UNSUPPORTED, "decode indefinite"); }

    /* Reserved AI 28 -> malformed */
    { uint8_t in[] = {0x1C}; /* uint with AI=28 */
      ctx.cbuf = in; ctx.bufSz = 1; ctx.idx = 0;
      ret = wc_CBOR_DecodeHead(&ctx, &item);
      TEST_ASSERT(ret == WOLFCOSE_E_CBOR_MALFORMED, "decode reserved AI"); }

    /* Empty buffer */
    { ctx.cbuf = buf; ctx.bufSz = 0; ctx.idx = 0;
      ret = wc_CBOR_DecodeHead(&ctx, &item);
      TEST_ASSERT(ret == WOLFCOSE_E_CBOR_MALFORMED, "decode empty buffer"); }

    /* DecodeInt: overflow (negative with val > INT64_MAX) handled gracefully */
    /* PeekType check */
    { uint8_t in[] = {0x83, 0x01};
      ctx.cbuf = in; ctx.bufSz = sizeof(in); ctx.idx = 0;
      TEST_ASSERT(wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_ARRAY,
                  "peek type array"); }

    /* Skip NULL ctx */
    ret = wc_CBOR_Skip(NULL);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "skip null ctx");

    /* DecodeInt with NULL val */
    /* cppcheck-suppress redundantAssignment */
    ctx.cbuf = buf; ctx.bufSz = sizeof(buf); ctx.idx = 0;
    buf[0] = 0x00;
    ret = wc_CBOR_DecodeInt(&ctx, NULL);
    TEST_ASSERT(ret == WOLFCOSE_E_INVALID_ARG, "decode int null val");

}

/* ----- Map with negative keys (COSE-style: -1, -2, -3) ----- */
static void test_cbor_negative_map_keys(void)
{
    uint8_t buf[64];
    WOLFCOSE_CBOR_CTX enc, dec;
    int ret;
    int64_t key;
    uint64_t val;

    printf("  [Negative map keys]\n");

    /* {1: 2, -1: 1, -2: h'AA'} -- COSE Key style */
    enc.buf = buf; enc.bufSz = sizeof(buf); enc.idx = 0;
    ret = wc_CBOR_EncodeMapStart(&enc, 3);
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&enc, 1);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&enc, 2);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeInt(&enc, -1);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeUint(&enc, 1);
    }
    if (ret == 0) {
        ret = wc_CBOR_EncodeInt(&enc, -2);
    }
    { uint8_t b = 0xAA;
      if (ret == 0) {
          ret = wc_CBOR_EncodeBstr(&enc, &b, 1);
      } }
    TEST_ASSERT(ret == 0, "neg keys encode");

    dec.cbuf = buf; dec.bufSz = enc.idx; dec.idx = 0;
    { size_t count;
      ret = wc_CBOR_DecodeMapStart(&dec, &count);
      TEST_ASSERT(ret == 0 && count == 3, "neg keys map 3"); }

    ret = wc_CBOR_DecodeInt(&dec, &key);
    TEST_ASSERT(ret == 0 && key == 1, "neg keys key=1");
    ret = wc_CBOR_DecodeUint(&dec, &val);
    TEST_ASSERT(ret == 0 && val == 2, "neg keys val=2");

    ret = wc_CBOR_DecodeInt(&dec, &key);
    TEST_ASSERT(ret == 0 && key == -1, "neg keys key=-1");
    ret = wc_CBOR_DecodeUint(&dec, &val);
    TEST_ASSERT(ret == 0 && val == 1, "neg keys val=1");

    ret = wc_CBOR_DecodeInt(&dec, &key);
    TEST_ASSERT(ret == 0 && key == -2, "neg keys key=-2");
    { const uint8_t* data; size_t dataLen;
      ret = wc_CBOR_DecodeBstr(&dec, &data, &dataLen);
      TEST_ASSERT(ret == 0 && dataLen == 1 && data[0] == 0xAA,
                  "neg keys val=h'AA'"); }
}

/* ----- Entry point ----- */
static void test_cbor_boundary_roundtrip(void)
{
    static const struct { uint64_t val; size_t len; } uvec[] = {
        {0u, 1u}, {23u, 1u}, {24u, 2u}, {255u, 2u}, {256u, 3u},
        {65535u, 3u}, {65536u, 5u}, {4294967295ULL, 5u},
        {4294967296ULL, 9u}
    };
    static const struct { int64_t val; size_t len; } ivec[] = {
        {-1, 1u}, {-24, 1u}, {-25, 2u}, {-256, 2u}, {-257, 3u},
        {-65536, 3u}, {-65537, 5u},
        {-4294967296LL, 5u}, {-4294967297LL, 9u}, {INT64_MIN, 9u}
    };
    uint8_t buf[16];
    WOLFCOSE_CBOR_CTX ctx;
    uint64_t uval;
    int64_t ival;
    int ret;
    size_t i;

    printf("  [Boundary Round-trip]\n");

    for (i = 0; i < (sizeof(uvec) / sizeof(uvec[0])); i++) {
        ctx.buf = buf; ctx.bufSz = sizeof(buf); ctx.idx = 0;
        ret = wc_CBOR_EncodeUint(&ctx, uvec[i].val);
        TEST_ASSERT(ret == 0 && ctx.idx == uvec[i].len,
                    "uint boundary encode len");
        ctx.cbuf = buf; ctx.bufSz = ctx.idx; ctx.idx = 0;
        ret = wc_CBOR_DecodeUint(&ctx, &uval);
        TEST_ASSERT(ret == 0 && uval == uvec[i].val,
                    "uint boundary decode");
    }

    for (i = 0; i < (sizeof(ivec) / sizeof(ivec[0])); i++) {
        ctx.buf = buf; ctx.bufSz = sizeof(buf); ctx.idx = 0;
        ret = wc_CBOR_EncodeInt(&ctx, ivec[i].val);
        TEST_ASSERT(ret == 0 && ctx.idx == ivec[i].len,
                    "negint boundary encode len");
        ctx.cbuf = buf; ctx.bufSz = ctx.idx; ctx.idx = 0;
        ret = wc_CBOR_DecodeInt(&ctx, &ival);
        TEST_ASSERT(ret == 0 && ival == ivec[i].val,
                    "negint boundary decode");
    }
}

static void test_cbor_peektype_bounds(void)
{
    WOLFCOSE_CBOR_CTX ctx;
    uint8_t buf[1] = {0x40};

    printf("  [PeekType bounds]\n");

    ctx.cbuf = buf; ctx.bufSz = sizeof(buf); ctx.idx = 0;
    TEST_ASSERT(wc_CBOR_PeekType(&ctx) == WOLFCOSE_CBOR_BSTR,
                "peektype valid");

    ctx.idx = sizeof(buf);
    TEST_ASSERT(wc_CBOR_PeekType(&ctx) == 0xFFu,
                "peektype exhausted sentinel");

    TEST_ASSERT(wc_CBOR_PeekType(NULL) == 0xFFu, "peektype null sentinel");
}

static void test_cbor_ctx_init(void)
{
    WOLFCOSE_CBOR_CTX ctx;
    uint8_t buf[16];
    uint64_t uval = 0;
    int ret;

    printf("  [Context initialisers]\n");

    /* Poison every field so a partial init is visible. */
    ctx.buf = (uint8_t*)0x1;
    ctx.cbuf = (const uint8_t*)0x1;
    ctx.bufSz = 0xDEAD;
    ctx.idx = 0xBEEF;

    ret = wc_CBOR_EncoderInit(&ctx, buf, sizeof(buf));
    TEST_ASSERT(ret == 0 && ctx.buf == buf && ctx.cbuf == NULL &&
                ctx.bufSz == sizeof(buf) && ctx.idx == 0,
                "encoder init sets encode side only");
    ret = wc_CBOR_EncodeUint(&ctx, 1000);
    TEST_ASSERT(ret == 0 && ctx.idx == 3, "encoder init usable");

    ret = wc_CBOR_DecoderInit(&ctx, buf, ctx.idx);
    TEST_ASSERT(ret == 0 && ctx.cbuf == buf && ctx.buf == NULL &&
                ctx.bufSz == 3 && ctx.idx == 0,
                "decoder init sets decode side only");
    ret = wc_CBOR_DecodeUint(&ctx, &uval);
    TEST_ASSERT(ret == 0 && uval == 1000, "decoder init usable");

    TEST_ASSERT(wc_CBOR_EncoderInit(NULL, buf, sizeof(buf)) ==
                WOLFCOSE_E_INVALID_ARG, "encoder init null ctx");
    TEST_ASSERT(wc_CBOR_EncoderInit(&ctx, NULL, 4) ==
                WOLFCOSE_E_INVALID_ARG, "encoder init null buf");
    TEST_ASSERT(wc_CBOR_DecoderInit(NULL, buf, 4) ==
                WOLFCOSE_E_INVALID_ARG, "decoder init null ctx");
    TEST_ASSERT(wc_CBOR_DecoderInit(&ctx, NULL, 4) ==
                WOLFCOSE_E_INVALID_ARG, "decoder init null buf");
}

static void test_cbor_skip_item(void)
{
    WOLFCOSE_CBOR_CTX ctx;
    uint8_t buf[64];
    const uint8_t* item = NULL;
    size_t itemLen = 0;
    size_t nestedStart;
    int ret;

    printf("  [SkipItem capture]\n");

    /* [1, {1: "a", 2: [3, 4]}, 5] -- capture the middle map verbatim. */
    (void)wc_CBOR_EncoderInit(&ctx, buf, sizeof(buf));
    (void)wc_CBOR_EncodeArrayStart(&ctx, 3);
    (void)wc_CBOR_EncodeUint(&ctx, 1);
    nestedStart = ctx.idx;
    (void)wc_CBOR_EncodeMapStart(&ctx, 2);
    (void)wc_CBOR_EncodeUint(&ctx, 1);
    (void)wc_CBOR_EncodeTstr(&ctx, (const uint8_t*)"a", 1);
    (void)wc_CBOR_EncodeUint(&ctx, 2);
    (void)wc_CBOR_EncodeArrayStart(&ctx, 2);
    (void)wc_CBOR_EncodeUint(&ctx, 3);
    (void)wc_CBOR_EncodeUint(&ctx, 4);
    /* empty-brace-scan: allow - test-local temporary scope */
    {
        size_t nestedLen = ctx.idx - nestedStart;
        size_t total;
        size_t count = 0;
        uint64_t uval = 0;

        (void)wc_CBOR_EncodeUint(&ctx, 5);
        total = ctx.idx;

        (void)wc_CBOR_DecoderInit(&ctx, buf, total);
        ret = wc_CBOR_DecodeArrayStart(&ctx, &count);
        TEST_ASSERT(ret == 0 && count == 3, "skipitem outer array");
        ret = wc_CBOR_DecodeUint(&ctx, &uval);
        TEST_ASSERT(ret == 0 && uval == 1, "skipitem first element");

        ret = wc_CBOR_SkipItem(&ctx, &item, &itemLen);
        TEST_ASSERT(ret == 0 && item == &buf[nestedStart] &&
                    itemLen == nestedLen,
                    "skipitem captures the nested map exactly");

        ret = wc_CBOR_DecodeUint(&ctx, &uval);
        TEST_ASSERT(ret == 0 && uval == 5 && ctx.idx == total,
                    "skipitem leaves the cursor after the item");

        /* The captured bytes must parse standalone. */
        /* empty-brace-scan: allow - test-local temporary scope */
        {
            WOLFCOSE_CBOR_CTX sub;
            size_t subCount = 0;

            (void)wc_CBOR_DecoderInit(&sub, item, itemLen);
            ret = wc_CBOR_DecodeMapStart(&sub, &subCount);
            TEST_ASSERT(ret == 0 && subCount == 2,
                        "skipitem capture reparses standalone");
        }
    }

    TEST_ASSERT(wc_CBOR_SkipItem(NULL, &item, &itemLen) ==
                WOLFCOSE_E_INVALID_ARG, "skipitem null ctx");
    (void)wc_CBOR_DecoderInit(&ctx, buf, sizeof(buf));
    TEST_ASSERT(wc_CBOR_SkipItem(&ctx, NULL, &itemLen) ==
                WOLFCOSE_E_INVALID_ARG, "skipitem null data");
    TEST_ASSERT(wc_CBOR_SkipItem(&ctx, &item, NULL) ==
                WOLFCOSE_E_INVALID_ARG, "skipitem null len");

    /* Truncated input: the underlying skip fails and nothing is reported. */
    /* empty-brace-scan: allow - test-local temporary scope */
    {
        static const uint8_t trunc[] = {0x82, 0x01};  /* array(2), one item */
        item = NULL;
        itemLen = 0;
        (void)wc_CBOR_DecoderInit(&ctx, trunc, sizeof(trunc));
        ret = wc_CBOR_SkipItem(&ctx, &item, &itemLen);
        TEST_ASSERT(ret != 0 && item == NULL && itemLen == 0,
                    "skipitem truncated input fails");
    }
}

static void test_cbor_decode_label(void)
{
    WOLFCOSE_CBOR_CTX ctx;
    WOLFCOSE_CBOR_LABEL label;
    uint8_t buf[64];
    static const uint8_t algText[] = "alg";
    static const uint8_t validUtf8[] = {
        0x6Du, 0xC2u, 0x80u, 0xE0u, 0xA0u, 0x80u,
        0xF0u, 0x90u, 0x80u, 0x80u, 0xF4u, 0x8Fu, 0xBFu, 0xBFu
    };
    static const uint8_t truncatedUtf8[] = {0x61u, 0xC2u};
    static const uint8_t overlongUtf8[] = {0x62u, 0xC0u, 0xAFu};
    static const uint8_t surrogateUtf8[] = {
        0x63u, 0xEDu, 0xA0u, 0x80u
    };
    static const uint8_t outOfRangeUtf8[] = {
        0x64u, 0xF4u, 0x90u, 0x80u, 0x80u
    };
    int ret;

    printf("  [Int-or-text labels]\n");

    /* {3: 1, "alg": 2, -1: 3} */
    (void)wc_CBOR_EncoderInit(&ctx, buf, sizeof(buf));
    (void)wc_CBOR_EncodeMapStart(&ctx, 3);
    (void)wc_CBOR_EncodeUint(&ctx, 3);
    (void)wc_CBOR_EncodeUint(&ctx, 1);
    (void)wc_CBOR_EncodeTstr(&ctx, algText, 3);
    (void)wc_CBOR_EncodeUint(&ctx, 2);
    (void)wc_CBOR_EncodeInt(&ctx, -1);
    (void)wc_CBOR_EncodeUint(&ctx, 3);

    /* empty-brace-scan: allow - test-local temporary scope */
    {
        size_t count = 0;
        uint64_t uval = 0;

        (void)wc_CBOR_DecoderInit(&ctx, buf, ctx.idx);
        ret = wc_CBOR_DecodeMapStart(&ctx, &count);
        TEST_ASSERT(ret == 0 && count == 3, "label map start");

        ret = wc_CBOR_DecodeLabel(&ctx, &label);
        TEST_ASSERT(ret == 0 && label.isText == 0 && label.val == 3,
                    "label int 3");
        TEST_ASSERT(wc_CBOR_LabelIsInt(&label, 3) == 1, "label int matches");
        TEST_ASSERT(wc_CBOR_LabelIsInt(&label, 4) == 0, "label int mismatch");
        TEST_ASSERT(wc_CBOR_LabelIsText(&label, algText, 3) == 0,
                    "int label is not text");
        (void)wc_CBOR_DecodeUint(&ctx, &uval);

        ret = wc_CBOR_DecodeLabel(&ctx, &label);
        TEST_ASSERT(ret == 0 && label.isText == 1 && label.textLen == 3 &&
                    memcmp(label.text, algText, 3) == 0, "label tstr alg");
        TEST_ASSERT(wc_CBOR_LabelIsText(&label, algText, 3) == 1,
                    "label text matches");
        TEST_ASSERT(wc_CBOR_LabelIsText(&label, algText, 2) == 0,
                    "label text length mismatch");
        TEST_ASSERT(wc_CBOR_LabelIsText(&label, (const uint8_t*)"blg", 3) == 0,
                    "label text value mismatch");
        TEST_ASSERT(wc_CBOR_LabelIsInt(&label, 3) == 0,
                    "text label is not int");
        (void)wc_CBOR_DecodeUint(&ctx, &uval);

        ret = wc_CBOR_DecodeLabel(&ctx, &label);
        TEST_ASSERT(ret == 0 && label.isText == 0 && label.val == -1,
                    "label negint -1");
        TEST_ASSERT(wc_CBOR_LabelIsInt(&label, -1) == 1,
                    "label negint matches");
    }

    (void)wc_CBOR_DecoderInit(&ctx, validUtf8, sizeof(validUtf8));
    ret = wc_CBOR_DecodeLabel(&ctx, &label);
    TEST_ASSERT(ret == WOLFCOSE_SUCCESS && label.isText == 1u &&
                label.textLen == (sizeof(validUtf8) - 1u),
                "label accepts valid UTF-8 boundaries");

    (void)wc_CBOR_DecoderInit(&ctx, truncatedUtf8, sizeof(truncatedUtf8));
    ret = wc_CBOR_DecodeLabel(&ctx, &label);
    TEST_ASSERT(ret == WOLFCOSE_E_CBOR_MALFORMED,
                "label rejects truncated UTF-8");

    (void)wc_CBOR_DecoderInit(&ctx, overlongUtf8, sizeof(overlongUtf8));
    ret = wc_CBOR_DecodeLabel(&ctx, &label);
    TEST_ASSERT(ret == WOLFCOSE_E_CBOR_MALFORMED,
                "label rejects overlong UTF-8");

    (void)wc_CBOR_DecoderInit(&ctx, surrogateUtf8, sizeof(surrogateUtf8));
    ret = wc_CBOR_DecodeLabel(&ctx, &label);
    TEST_ASSERT(ret == WOLFCOSE_E_CBOR_MALFORMED,
                "label rejects UTF-8 surrogate");

    (void)wc_CBOR_DecoderInit(&ctx, outOfRangeUtf8,
                              sizeof(outOfRangeUtf8));
    ret = wc_CBOR_DecodeLabel(&ctx, &label);
    TEST_ASSERT(ret == WOLFCOSE_E_CBOR_MALFORMED,
                "label rejects UTF-8 above U+10FFFF");

    /* A label argument above INT64_MAX has no int64_t spelling, in either
     * sign. The negint boundary is one step further out: RFC 8949 encodes -n
     * as n-1, so argument INT64_MAX is INT64_MIN and still valid. */
    /* empty-brace-scan: allow - test-local temporary scope */
    {
        /* uint 0xFFFFFFFFFFFFFFFF = 2^64-1 */
        static const uint8_t bigUint[] = {
            0x1Bu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu
        };
        /* uint 0x8000000000000000 = INT64_MAX + 1 */
        static const uint8_t justOver[] = {
            0x1Bu, 0x80u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
        };
        /* negint arg 0x7FFFFFFFFFFFFFFF = INT64_MAX -> INT64_MIN */
        static const uint8_t minInt[] = {
            0x3Bu, 0x7Fu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu
        };
        /* negint arg 0x8000000000000000 -> one below INT64_MIN */
        static const uint8_t belowMin[] = {
            0x3Bu, 0x80u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
        };

        (void)wc_CBOR_DecoderInit(&ctx, bigUint, sizeof(bigUint));
        ret = wc_CBOR_DecodeLabel(&ctx, &label);
        TEST_ASSERT(ret == WOLFCOSE_E_CBOR_OVERFLOW,
                    "label uint 2^64-1 overflows");

        (void)wc_CBOR_DecoderInit(&ctx, justOver, sizeof(justOver));
        ret = wc_CBOR_DecodeLabel(&ctx, &label);
        TEST_ASSERT(ret == WOLFCOSE_E_CBOR_OVERFLOW,
                    "label uint INT64_MAX+1 overflows");

        (void)wc_CBOR_DecoderInit(&ctx, minInt, sizeof(minInt));
        ret = wc_CBOR_DecodeLabel(&ctx, &label);
        TEST_ASSERT(ret == 0 && label.isText == 0 && label.val == INT64_MIN,
                    "label negint INT64_MIN");

        (void)wc_CBOR_DecoderInit(&ctx, belowMin, sizeof(belowMin));
        ret = wc_CBOR_DecodeLabel(&ctx, &label);
        TEST_ASSERT(ret == WOLFCOSE_E_CBOR_OVERFLOW,
                    "label negint below INT64_MIN overflows");
    }

    /* A bstr is not a valid label. */
    (void)wc_CBOR_EncoderInit(&ctx, buf, sizeof(buf));
    (void)wc_CBOR_EncodeBstr(&ctx, algText, 3);
    /* empty-brace-scan: allow - test-local temporary scope */
    {
        size_t encLen = ctx.idx;
        (void)wc_CBOR_DecoderInit(&ctx, buf, encLen);
        ret = wc_CBOR_DecodeLabel(&ctx, &label);
        TEST_ASSERT(ret == WOLFCOSE_E_CBOR_TYPE, "bstr rejected as label");
    }

    TEST_ASSERT(wc_CBOR_DecodeLabel(NULL, &label) == WOLFCOSE_E_INVALID_ARG,
                "label null ctx");
    TEST_ASSERT(wc_CBOR_DecodeLabel(&ctx, NULL) == WOLFCOSE_E_INVALID_ARG,
                "label null out");
    TEST_ASSERT(wc_CBOR_LabelIsInt(NULL, 0) == 0, "label int null safe");
    TEST_ASSERT(wc_CBOR_LabelIsText(NULL, algText, 3) == 0,
                "label text null safe");
}

int test_cbor(void)
{
    g_failures = 0;

    test_cbor_encode_vectors();
    test_cbor_decode_vectors();
    test_cbor_roundtrip();
    test_cbor_boundary_roundtrip();
    test_cbor_peektype_bounds();
    test_cbor_ctx_init();
    test_cbor_skip_item();
    test_cbor_decode_label();
    test_cbor_nested();
    test_cbor_skip();
    test_cbor_skip_depth();
    test_cbor_skip_tainted_count();
    test_cbor_decode_simple_not_well_formed();
    test_cbor_encode_bstr_null_with_len();
    test_cbor_encode_idx_past_bufsz();
    test_cbor_reject_non_preferred();
    test_cbor_errors();
    test_cbor_negative_map_keys();

    printf("  CBOR: %d failure(s)\n", g_failures);
    return g_failures;
}
