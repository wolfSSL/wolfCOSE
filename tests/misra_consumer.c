/* Analyzer-only consumer for whole-program MISRA checks.
 *
 * This translation unit models a downstream application. It is parsed by
 * cppcheck but is never linked or shipped. Public symbols are referenced so
 * Rule 8.7 is evaluated at the library boundary instead of one source file.
 */

#include <wolfcose/wolfcose.h>

#define WOLFCOSE_MISRA_USE_API(name) total += sizeof(&(name))

static size_t wolfCose_MisraUsePublicApis(void)
{
    size_t total = 0u;

    WOLFCOSE_MISRA_USE_API(wc_CBOR_EncodeUint);
    WOLFCOSE_MISRA_USE_API(wc_CBOR_EncodeInt);
    WOLFCOSE_MISRA_USE_API(wc_CBOR_EncodeBstr);
    WOLFCOSE_MISRA_USE_API(wc_CBOR_EncodeTstr);
    WOLFCOSE_MISRA_USE_API(wc_CBOR_EncodeArrayStart);
    WOLFCOSE_MISRA_USE_API(wc_CBOR_EncodeMapStart);
    WOLFCOSE_MISRA_USE_API(wc_CBOR_EncodeTag);
    WOLFCOSE_MISRA_USE_API(wc_CBOR_EncodeTrue);
    WOLFCOSE_MISRA_USE_API(wc_CBOR_EncodeFalse);
    WOLFCOSE_MISRA_USE_API(wc_CBOR_EncodeNull);
#ifdef WOLFCOSE_FLOAT
    WOLFCOSE_MISRA_USE_API(wc_CBOR_EncodeFloat);
    WOLFCOSE_MISRA_USE_API(wc_CBOR_EncodeDouble);
#endif
    WOLFCOSE_MISRA_USE_API(wc_CBOR_DecodeHead);
    WOLFCOSE_MISRA_USE_API(wc_CBOR_DecodeUint);
    WOLFCOSE_MISRA_USE_API(wc_CBOR_DecodeInt);
    WOLFCOSE_MISRA_USE_API(wc_CBOR_DecodeBstr);
    WOLFCOSE_MISRA_USE_API(wc_CBOR_DecodeTstr);
    WOLFCOSE_MISRA_USE_API(wc_CBOR_DecodeArrayStart);
    WOLFCOSE_MISRA_USE_API(wc_CBOR_DecodeMapStart);
    WOLFCOSE_MISRA_USE_API(wc_CBOR_DecodeTag);
    WOLFCOSE_MISRA_USE_API(wc_CBOR_Skip);
    WOLFCOSE_MISRA_USE_API(wc_CBOR_SkipItem);
    WOLFCOSE_MISRA_USE_API(wc_CBOR_DecodeLabel);
    WOLFCOSE_MISRA_USE_API(wc_CBOR_LabelIsInt);
    WOLFCOSE_MISRA_USE_API(wc_CBOR_LabelIsText);
    WOLFCOSE_MISRA_USE_API(wc_CoseKey_Init);
    WOLFCOSE_MISRA_USE_API(wc_CoseKey_Free);
#ifdef HAVE_ECC
    WOLFCOSE_MISRA_USE_API(wc_CoseKey_SetEcc);
#endif
#ifdef WOLFCOSE_HAVE_EDDSA
    WOLFCOSE_MISRA_USE_API(wc_CoseKey_SetEd25519);
#endif
#ifdef WOLFCOSE_HAVE_ED448
    WOLFCOSE_MISRA_USE_API(wc_CoseKey_SetEd448);
#endif
#ifdef WOLFCOSE_HAVE_MLDSA
    WOLFCOSE_MISRA_USE_API(wc_CoseKey_SetMlDsa);
    WOLFCOSE_MISRA_USE_API(wc_CoseKey_SetMlDsa_ex);
#endif
#ifdef WOLFCOSE_HAVE_RSAPSS
    WOLFCOSE_MISRA_USE_API(wc_CoseKey_SetRsa);
#endif
    WOLFCOSE_MISRA_USE_API(wc_CoseKey_SetSymmetric);
#ifdef WOLFCOSE_EXT_SIGN
    WOLFCOSE_MISRA_USE_API(wc_CoseKey_SetExtSigner);
#endif
#ifdef WOLFCOSE_KEY_ENCODE
    WOLFCOSE_MISRA_USE_API(wc_CoseKey_Encode);
    WOLFCOSE_MISRA_USE_API(wc_CoseKey_Encode_ex);
#ifdef HAVE_ECC
    WOLFCOSE_MISRA_USE_API(wc_CoseKey_EncodeEccRaw);
#endif
    WOLFCOSE_MISRA_USE_API(wc_CoseKey_EncodeSize);
    WOLFCOSE_MISRA_USE_API(wc_CoseKey_EncodeSize_ex);
#endif
#ifdef WOLFCOSE_KEY_DECODE
    WOLFCOSE_MISRA_USE_API(wc_CoseKey_PeekInfo);
    WOLFCOSE_MISRA_USE_API(wc_CoseKey_Decode);
#endif
#ifdef WOLFCOSE_SIGN1_SIGN
    WOLFCOSE_MISRA_USE_API(wc_CoseSign1_Sign);
    WOLFCOSE_MISRA_USE_API(wc_CoseSign1_Sign_ex);
    WOLFCOSE_MISRA_USE_API(wc_CoseSign1_SignSize_ex);
#endif
#ifdef WOLFCOSE_SIGN1_VERIFY
    WOLFCOSE_MISRA_USE_API(wc_CoseSign1_Verify);
#endif
#ifdef WOLFCOSE_COUNTERSIGN_SIGN
    WOLFCOSE_MISRA_USE_API(wc_Cose_AddCounterSignature);
    WOLFCOSE_MISRA_USE_API(wc_Cose_AddCounterSignature0);
#endif
#ifdef WOLFCOSE_COUNTERSIGN_VERIFY
    WOLFCOSE_MISRA_USE_API(wc_Cose_VerifyCounterSignature);
    WOLFCOSE_MISRA_USE_API(wc_Cose_VerifyCounterSignature0);
#endif
#ifdef WOLFCOSE_ENCRYPT0_ENCRYPT
    WOLFCOSE_MISRA_USE_API(wc_CoseEncrypt0_Encrypt);
#endif
#ifdef WOLFCOSE_ENCRYPT0_DECRYPT
    WOLFCOSE_MISRA_USE_API(wc_CoseEncrypt0_Decrypt);
#endif
#ifdef WOLFCOSE_MAC0_CREATE
    WOLFCOSE_MISRA_USE_API(wc_CoseMac0_Create);
#endif
#ifdef WOLFCOSE_MAC0_VERIFY
    WOLFCOSE_MISRA_USE_API(wc_CoseMac0_Verify);
#endif
#ifdef WOLFCOSE_SIGN_SIGN
    WOLFCOSE_MISRA_USE_API(wc_CoseSign_Sign);
#endif
#ifdef WOLFCOSE_SIGN_VERIFY
    WOLFCOSE_MISRA_USE_API(wc_CoseSign_Verify);
#endif
#ifdef WOLFCOSE_ENCRYPT_ENCRYPT
    WOLFCOSE_MISRA_USE_API(wc_CoseEncrypt_Encrypt);
#endif
#ifdef WOLFCOSE_ENCRYPT_DECRYPT
    WOLFCOSE_MISRA_USE_API(wc_CoseEncrypt_Decrypt);
#endif
#ifdef WOLFCOSE_MAC_CREATE
    WOLFCOSE_MISRA_USE_API(wc_CoseMac_Create);
#endif
#ifdef WOLFCOSE_MAC_VERIFY
    WOLFCOSE_MISRA_USE_API(wc_CoseMac_Verify);
#endif

    return total;
}

int main(void)
{
    /* These public compatibility and reserved constants are intentionally not
     * consumed by the library itself. Expanding them here models application
     * use. */
    static const volatile int32_t publicConstants[] = {
        WOLFCOSE_E_COSE_MAC_FAIL,
        (int32_t)WOLFCOSE_CBOR_BREAK,
        (int32_t)WOLFCOSE_CBOR_AI_FLOAT16,
        WOLFCOSE_ALG_HMAC256,
        WOLFCOSE_ALG_HMAC384,
        WOLFCOSE_ALG_HMAC512,
        WOLFCOSE_ALG_ECDH_SS_HKDF_256,
        WOLFCOSE_ALG_ECDH_SS_HKDF_512,
        WOLFCOSE_ALG_ECDH_ES_A128KW,
        WOLFCOSE_ALG_ECDH_ES_A192KW,
        WOLFCOSE_ALG_ECDH_ES_A256KW,
        (int32_t)WOLFCOSE_TAG_COUNTERSIGNATURE,
        WOLFCOSE_CRV_ML_DSA_44,
        WOLFCOSE_CRV_ML_DSA_65,
        WOLFCOSE_CRV_ML_DSA_87,
        (int32_t)LIBWOLFCOSE_VERSION_HEX
    };
    size_t used = wolfCose_MisraUsePublicApis();

    used += sizeof(publicConstants);
    if (publicConstants[0] == INT32_MIN) {
        used = 0u;
    }
    used += sizeof(LIBWOLFCOSE_VERSION_STRING);
#ifdef WOLFCOSE_RECIPIENTS
    used += 1u;
#endif
#ifdef WOLFCOSE_ECDH
    used += 1u;
#endif
#ifdef WOLFCOSE_ECDH_WRAP
    used += 1u;
#endif

    return (used == 0u) ? 1 : 0;
}
