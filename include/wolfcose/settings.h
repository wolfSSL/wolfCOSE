/* settings.h
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

/* wolfCOSE compile-time configuration.
 *
 * Default: every algorithm wolfSSL provides is enabled (full build). Strip an
 * individual feature with WOLFCOSE_NO_<X>.
 *
 * WOLFCOSE_LEAN: lean build. Only the core stays on — COSE_Sign1/Encrypt0/Mac0
 * with ES256, AES-GCM, HMAC-SHA256 — and everything else becomes opt-in via
 * WOLFCOSE_ENABLE_<X>.
 *
 * An extension is on when: explicitly enabled (WOLFCOSE_ENABLE_<X>), or it is a
 * full (non-LEAN) build and wolfSSL provides the primitive and it is not opted
 * out. Explicitly enabling something wolfSSL cannot provide is a hard error.
 *
 * Configure via -D flags or the wolfSSL user_settings.h (included before this).
 */

#ifndef WOLFCOSE_SETTINGS_H
#define WOLFCOSE_SETTINGS_H

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/version.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ----- Convenience profiles -----
 * One define each; footprint numbers and rationale live in docs/Macros.md.
 * Each switch is set only if the user has not already chosen it. */

/* Smallest verify-only COSE_Sign1 (ES256). */
#ifdef WOLFCOSE_LEAN_VERIFY
    #ifndef WOLFCOSE_LEAN
        #define WOLFCOSE_LEAN
    #endif
    #ifndef WOLFCOSE_NO_SIGN1_SIGN
        #define WOLFCOSE_NO_SIGN1_SIGN
    #endif
    #ifndef WOLFCOSE_NO_ENCRYPT0
        #define WOLFCOSE_NO_ENCRYPT0
    #endif
    #ifndef WOLFCOSE_NO_MAC0
        #define WOLFCOSE_NO_MAC0
    #endif
    #ifndef WOLFCOSE_NO_KEY_ENCODE
        #define WOLFCOSE_NO_KEY_ENCODE
    #endif
    #ifndef WOLFCOSE_NO_KEY_DECODE
        #define WOLFCOSE_NO_KEY_DECODE
    #endif
#endif /* WOLFCOSE_LEAN_VERIFY */

/* Verify-only COSE_Sign1 with ML-DSA (implies WOLFCOSE_LEAN_MLDSA, no signing). */
#ifdef WOLFCOSE_LEAN_VERIFY_MLDSA
    #ifndef WOLFCOSE_LEAN_MLDSA
        #define WOLFCOSE_LEAN_MLDSA
    #endif
    #ifndef WOLFCOSE_NO_SIGN1_SIGN
        #define WOLFCOSE_NO_SIGN1_SIGN
    #endif
#endif /* WOLFCOSE_LEAN_VERIFY_MLDSA */

/* Lean ML-DSA-only COSE_Sign1 sign+verify (no ES256, Sign1 only). */
#ifdef WOLFCOSE_LEAN_MLDSA
    #ifndef WOLFCOSE_LEAN
        #define WOLFCOSE_LEAN
    #endif
    #ifndef WOLFCOSE_ENABLE_MLDSA
        #define WOLFCOSE_ENABLE_MLDSA
    #endif
    #ifndef WOLFCOSE_NO_ES256
        #define WOLFCOSE_NO_ES256
    #endif
    #ifndef WOLFCOSE_NO_ENCRYPT0
        #define WOLFCOSE_NO_ENCRYPT0
    #endif
    #ifndef WOLFCOSE_NO_MAC0
        #define WOLFCOSE_NO_MAC0
    #endif
    #ifndef WOLFCOSE_NO_KEY_ENCODE
        #define WOLFCOSE_NO_KEY_ENCODE
    #endif
    #ifndef WOLFCOSE_NO_KEY_DECODE
        #define WOLFCOSE_NO_KEY_DECODE
    #endif
#endif /* WOLFCOSE_LEAN_MLDSA */

/* ----- Integration seams -----
 *
 * Opt-in in every build, including a full one. These are not algorithms, so
 * there is no "wolfSSL provides the primitive" clause to auto-enable them and a
 * default build is byte-identical to one built without them.
 * ----- */

/* External/delegated signing: the caller supplies the signature over the
 * to-be-signed bytes, so no private key material enters wolfCOSE — extension. */
#if defined(WOLFCOSE_ENABLE_EXT_SIGN)
    #define WOLFCOSE_EXT_SIGN
#endif

/* ----- Experimental (draft, pre-RFC) features -----
 * Draft or unstable features — IETF Internet-Drafts not yet finalized as an
 * RFC, where the wire format or API may still change — require an explicit
 * acknowledgement. WOLFCOSE_EXPERIMENTAL enables no functionality on its own; it
 * only permits the individually selected experimental features below, each of
 * which keeps its own WOLFCOSE_ENABLE_<X> opt-in. See docs/Macros.md.
 *
 * Every experimental feature copies the guard form below into its own section:
 * enabling the feature without WOLFCOSE_EXPERIMENTAL is a hard error. */

/* Reference exemplar and validation target. Enables no functionality; it exists
 * only to document the pattern and let CI exercise the acknowledgement gate. */
#if defined(WOLFCOSE_ENABLE_EXPERIMENTAL_EXAMPLE) && !defined(WOLFCOSE_EXPERIMENTAL)
    #error "WOLFCOSE_ENABLE_EXPERIMENTAL_EXAMPLE selects experimental draft code (spec not yet a finalized RFC); also define WOLFCOSE_EXPERIMENTAL to acknowledge"
#endif

/* ----- Signature algorithms ----- */

/* ES256 — core (on whenever wolfSSL has ECC) */
#if defined(HAVE_ECC) && !defined(WOLFCOSE_NO_ES256)
    #define WOLFCOSE_HAVE_ES256
#endif

/* ES384 — extension */
#if defined(WOLFCOSE_ENABLE_ES384)
    #if !defined(HAVE_ECC) || !defined(WOLFSSL_SHA384)
        #error "WOLFCOSE_ENABLE_ES384 requires wolfSSL HAVE_ECC + WOLFSSL_SHA384"
    #endif
    #define WOLFCOSE_HAVE_ES384
#elif !defined(WOLFCOSE_LEAN) && !defined(WOLFCOSE_NO_ES384) && \
      defined(HAVE_ECC) && defined(WOLFSSL_SHA384)
    #define WOLFCOSE_HAVE_ES384
#endif

/* ES512 — extension */
#if defined(WOLFCOSE_ENABLE_ES512)
    #if !defined(HAVE_ECC) || !defined(WOLFSSL_SHA512)
        #error "WOLFCOSE_ENABLE_ES512 requires wolfSSL HAVE_ECC + WOLFSSL_SHA512"
    #endif
    #define WOLFCOSE_HAVE_ES512
#elif !defined(WOLFCOSE_LEAN) && !defined(WOLFCOSE_NO_ES512) && \
      defined(HAVE_ECC) && defined(WOLFSSL_SHA512)
    #define WOLFCOSE_HAVE_ES512
#endif

/* EdDSA (Ed25519) — extension */
#if defined(WOLFCOSE_ENABLE_EDDSA)
    #ifndef HAVE_ED25519
        #error "WOLFCOSE_ENABLE_EDDSA requires wolfSSL HAVE_ED25519"
    #endif
    #define WOLFCOSE_HAVE_EDDSA
#elif !defined(WOLFCOSE_LEAN) && !defined(WOLFCOSE_NO_EDDSA) && defined(HAVE_ED25519)
    #define WOLFCOSE_HAVE_EDDSA
#endif

/* Ed448 — extension */
#if defined(WOLFCOSE_ENABLE_ED448)
    #ifndef HAVE_ED448
        #error "WOLFCOSE_ENABLE_ED448 requires wolfSSL HAVE_ED448"
    #endif
    #define WOLFCOSE_HAVE_ED448
#elif !defined(WOLFCOSE_LEAN) && !defined(WOLFCOSE_NO_ED448) && defined(HAVE_ED448)
    #define WOLFCOSE_HAVE_ED448
#endif

/* ML-DSA (44/65/87) — extension */
#if defined(WOLFCOSE_ENABLE_MLDSA)
    #ifndef WOLFSSL_HAVE_MLDSA
        #error "WOLFCOSE_ENABLE_MLDSA requires wolfSSL WOLFSSL_HAVE_MLDSA"
    #endif
    #define WOLFCOSE_HAVE_MLDSA
#elif !defined(WOLFCOSE_LEAN) && !defined(WOLFCOSE_NO_MLDSA) && defined(WOLFSSL_HAVE_MLDSA)
    #define WOLFCOSE_HAVE_MLDSA
#endif

/* RSA-PSS (PS256/384/512) — extension */
#if defined(WOLFCOSE_ENABLE_RSAPSS)
    #ifndef WC_RSA_PSS
        #error "WOLFCOSE_ENABLE_RSAPSS requires wolfSSL WC_RSA_PSS"
    #endif
    #define WOLFCOSE_RSAPSS_ON
#elif !defined(WOLFCOSE_LEAN) && !defined(WOLFCOSE_NO_RSAPSS) && defined(WC_RSA_PSS)
    #define WOLFCOSE_RSAPSS_ON
#endif
#ifdef WOLFCOSE_RSAPSS_ON
    #define WOLFCOSE_HAVE_PS256
    #ifdef WOLFSSL_SHA384
        #define WOLFCOSE_HAVE_PS384
    #endif
    #ifdef WOLFSSL_SHA512
        #define WOLFCOSE_HAVE_PS512
    #endif
#endif

#if defined(WOLFCOSE_HAVE_ES256) || defined(WOLFCOSE_HAVE_ES384) || \
    defined(WOLFCOSE_HAVE_ES512)
    #define WOLFCOSE_HAVE_ECDSA
#endif
#if defined(WOLFCOSE_HAVE_PS256) || defined(WOLFCOSE_HAVE_PS384) || \
    defined(WOLFCOSE_HAVE_PS512)
    #define WOLFCOSE_HAVE_RSAPSS
#endif
/* Private RSA round-trip needs wc_export_int + RsaKey.u; else public-only. */
#if defined(WOLFCOSE_HAVE_RSAPSS) && !defined(WOLFCOSE_RSA_PUBLIC_ONLY) && \
    !defined(WOLFSSL_RSA_PUBLIC_ONLY) && \
    (defined(HAVE_ECC) || defined(WOLFSSL_EXPORT_INT)) && \
    (defined(WOLFSSL_KEY_GEN) || defined(OPENSSL_EXTRA) || !defined(RSA_LOW_MEM))
    #define WOLFCOSE_HAVE_RSA_PRIVATE_KEY
#endif
#if defined(WOLFCOSE_HAVE_ECDSA) || defined(WOLFCOSE_HAVE_EDDSA) || \
    defined(WOLFCOSE_HAVE_ED448) || defined(WOLFCOSE_HAVE_RSAPSS) || \
    defined(WOLFCOSE_HAVE_MLDSA)
    #define WOLFCOSE_HAVE_SIG
#endif

/* ----- AEAD algorithms ----- */

/* AES-GCM — core */
#if defined(HAVE_AESGCM) && !defined(WOLFCOSE_NO_AESGCM)
    #define WOLFCOSE_HAVE_AESGCM
#endif

/* ChaCha20-Poly1305 — extension */
#if defined(WOLFCOSE_ENABLE_CHACHA20)
    #if !defined(HAVE_CHACHA) || !defined(HAVE_POLY1305)
        #error "WOLFCOSE_ENABLE_CHACHA20 requires wolfSSL HAVE_CHACHA + HAVE_POLY1305"
    #endif
    #define WOLFCOSE_HAVE_CHACHA20
#elif !defined(WOLFCOSE_LEAN) && !defined(WOLFCOSE_NO_CHACHA20) && \
      defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
    #define WOLFCOSE_HAVE_CHACHA20
#endif

/* AES-CCM — extension */
#if defined(WOLFCOSE_ENABLE_AESCCM)
    #ifndef HAVE_AESCCM
        #error "WOLFCOSE_ENABLE_AESCCM requires wolfSSL HAVE_AESCCM"
    #endif
    #define WOLFCOSE_HAVE_AESCCM
#elif !defined(WOLFCOSE_LEAN) && !defined(WOLFCOSE_NO_AESCCM) && defined(HAVE_AESCCM)
    #define WOLFCOSE_HAVE_AESCCM
#endif

#if defined(WOLFCOSE_HAVE_AESGCM) || defined(WOLFCOSE_HAVE_CHACHA20) || \
    defined(WOLFCOSE_HAVE_AESCCM)
    #define WOLFCOSE_HAVE_AEAD
#endif

/* ----- MAC algorithms ----- */

/* HMAC-SHA256 — core */
#if !defined(NO_HMAC) && !defined(WOLFCOSE_NO_HMAC256)
    #define WOLFCOSE_HAVE_HMAC256
#endif

/* HMAC-SHA384 — extension */
#if defined(WOLFCOSE_ENABLE_HMAC384)
    #if defined(NO_HMAC) || !defined(WOLFSSL_SHA384)
        #error "WOLFCOSE_ENABLE_HMAC384 requires wolfSSL HMAC + WOLFSSL_SHA384"
    #endif
    #define WOLFCOSE_HAVE_HMAC384
#elif !defined(WOLFCOSE_LEAN) && !defined(WOLFCOSE_NO_HMAC384) && \
      !defined(NO_HMAC) && defined(WOLFSSL_SHA384)
    #define WOLFCOSE_HAVE_HMAC384
#endif

/* HMAC-SHA512 — extension */
#if defined(WOLFCOSE_ENABLE_HMAC512)
    #if defined(NO_HMAC) || !defined(WOLFSSL_SHA512)
        #error "WOLFCOSE_ENABLE_HMAC512 requires wolfSSL HMAC + WOLFSSL_SHA512"
    #endif
    #define WOLFCOSE_HAVE_HMAC512
#elif !defined(WOLFCOSE_LEAN) && !defined(WOLFCOSE_NO_HMAC512) && \
      !defined(NO_HMAC) && defined(WOLFSSL_SHA512)
    #define WOLFCOSE_HAVE_HMAC512
#endif

/* AES-CBC-MAC — extension */
#if defined(WOLFCOSE_ENABLE_AESMAC)
    #ifndef HAVE_AES_CBC
        #error "WOLFCOSE_ENABLE_AESMAC requires wolfSSL HAVE_AES_CBC"
    #endif
    #define WOLFCOSE_HAVE_AESMAC
#elif !defined(WOLFCOSE_LEAN) && !defined(WOLFCOSE_NO_AESMAC) && defined(HAVE_AES_CBC)
    #define WOLFCOSE_HAVE_AESMAC
#endif

#if defined(WOLFCOSE_HAVE_HMAC256) || defined(WOLFCOSE_HAVE_HMAC384) || \
    defined(WOLFCOSE_HAVE_HMAC512)
    #define WOLFCOSE_HAVE_HMAC
#endif

#if defined(WOLFCOSE_HAVE_HMAC) || defined(WOLFCOSE_HAVE_AESMAC)
    #define WOLFCOSE_HAVE_MAC
#endif

/* ----- Message types ----- */

/* COSE_Sign1 — core (auto-off if no signature algorithm) */
#if !defined(WOLFCOSE_NO_SIGN1) && defined(WOLFCOSE_HAVE_SIG)
    #define WOLFCOSE_SIGN1
#endif
#ifdef WOLFCOSE_SIGN1
    #ifndef WOLFCOSE_NO_SIGN1_SIGN
        #define WOLFCOSE_SIGN1_SIGN
    #endif
    #ifndef WOLFCOSE_NO_SIGN1_VERIFY
        #define WOLFCOSE_SIGN1_VERIFY
    #endif
#endif

/* COSE_Encrypt0 — core (auto-off if no AEAD) */
#if !defined(WOLFCOSE_NO_ENCRYPT0) && defined(WOLFCOSE_HAVE_AEAD)
    #define WOLFCOSE_ENCRYPT0
#endif
#ifdef WOLFCOSE_ENCRYPT0
    #ifndef WOLFCOSE_NO_ENCRYPT0_ENCRYPT
        #define WOLFCOSE_ENCRYPT0_ENCRYPT
    #endif
    #ifndef WOLFCOSE_NO_ENCRYPT0_DECRYPT
        #define WOLFCOSE_ENCRYPT0_DECRYPT
    #endif
#endif

/* COSE_Mac0 — core (auto-off if no MAC) */
#if !defined(WOLFCOSE_NO_MAC0) && defined(WOLFCOSE_HAVE_MAC)
    #define WOLFCOSE_MAC0
#endif
#ifdef WOLFCOSE_MAC0
    #ifndef WOLFCOSE_NO_MAC0_CREATE
        #define WOLFCOSE_MAC0_CREATE
    #endif
    #ifndef WOLFCOSE_NO_MAC0_VERIFY
        #define WOLFCOSE_MAC0_VERIFY
    #endif
#endif

/* COSE_Sign multi-signer — extension */
#if defined(WOLFCOSE_ENABLE_SIGN)
    #define WOLFCOSE_SIGN_WANT
#elif !defined(WOLFCOSE_LEAN) && !defined(WOLFCOSE_NO_SIGN)
    #define WOLFCOSE_SIGN_WANT
#endif
#if defined(WOLFCOSE_SIGN_WANT) && defined(WOLFCOSE_HAVE_SIG)
    #define WOLFCOSE_SIGN
    #ifndef WOLFCOSE_NO_SIGN_SIGN
        #define WOLFCOSE_SIGN_SIGN
    #endif
    #ifndef WOLFCOSE_NO_SIGN_VERIFY
        #define WOLFCOSE_SIGN_VERIFY
    #endif
#endif

/* Exact enforcement of RFC 8230's 2048-bit RSA-PSS minimum needs access to
 * the modulus at the byte boundary. Backend-enabled builds may also carry
 * software keys, so verify-only builds must export the modulus. */
#if defined(WOLFCOSE_HAVE_RSAPSS) && \
    defined(WOLFSSL_RSA_VERIFY_ONLY) && !defined(HAVE_ECC) && \
    !defined(WOLFSSL_EXPORT_INT) && \
    (defined(WOLFCOSE_SIGN1_SIGN) || defined(WOLFCOSE_SIGN1_VERIFY) || \
     defined(WOLFCOSE_SIGN_SIGN) || defined(WOLFCOSE_SIGN_VERIFY))
    #error "wolfCOSE RSA-PSS key validation requires WOLFSSL_EXPORT_INT"
#endif

/* Optional RFC 6979 deterministic ECDSA signing. */
#if defined(WOLFCOSE_ENABLE_DETERMINISTIC_ECDSA) && \
    defined(WOLFCOSE_HAVE_ECDSA) && \
    (defined(WOLFCOSE_SIGN1_SIGN) || defined(WOLFCOSE_SIGN_SIGN)) && \
    !defined(WOLFCOSE_HAVE_DETERMINISTIC_ECDSA)
    #if !defined(WOLFSSL_ECDSA_DETERMINISTIC_K) && \
        !defined(WOLFSSL_ECDSA_DETERMINISTIC_K_VARIANT)
        #error "WOLFCOSE_ENABLE_DETERMINISTIC_ECDSA requires wolfSSL support"
    #endif

    #define WOLFCOSE_HAVE_DETERMINISTIC_ECDSA

    /* These wolfSSL sign dispatchers do not consume the key's deterministic
     * nonce state. Fail closed rather than silently bypassing the policy. The
     * Xilinx Versal path is not listed because it passes the derived nonce to
     * its hardware signer. */
    #if (defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_FIND)) || \
        defined(WOLF_CRYPTO_CB_ONLY_ECC) || \
        (defined(WOLFSSL_STM32_PKA) && \
         !defined(WC_STM32_PKA_VERIFY_ONLY)) || \
        defined(WOLFSSL_ATECC508A) || defined(WOLFSSL_ATECC608A) || \
        defined(WOLFSSL_MICROCHIP_TA100) || defined(PLUTON_CRYPTO_ECC) || \
        defined(WOLFSSL_CRYPTOCELL) || defined(WOLFSSL_SILABS_SE_ACCEL) || \
        defined(WOLFSSL_KCAPI_ECC) || \
        (defined(WOLFSSL_SE050) && \
         !defined(WOLFSSL_SE050_ONLY_KEY_ID)) || \
        (defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_ECC) && \
         (defined(HAVE_CAVIUM_V) || defined(HAVE_INTEL_QA)))
        #error "ECDSA backend does not support deterministic signing"
    #endif
#endif

/* COSE_Encrypt multi-recipient — extension */
#if defined(WOLFCOSE_ENABLE_ENCRYPT)
    #define WOLFCOSE_ENCRYPT_WANT
#elif !defined(WOLFCOSE_LEAN) && !defined(WOLFCOSE_NO_ENCRYPT)
    #define WOLFCOSE_ENCRYPT_WANT
#endif
#if defined(WOLFCOSE_ENCRYPT_WANT) && defined(WOLFCOSE_HAVE_AEAD)
    #define WOLFCOSE_ENCRYPT
    #ifndef WOLFCOSE_NO_ENCRYPT_ENCRYPT
        #define WOLFCOSE_ENCRYPT_ENCRYPT
    #endif
    #ifndef WOLFCOSE_NO_ENCRYPT_DECRYPT
        #define WOLFCOSE_ENCRYPT_DECRYPT
    #endif
#endif

/* COSE_Mac multi-recipient — extension */
#if defined(WOLFCOSE_ENABLE_MAC)
    #define WOLFCOSE_MAC_WANT
#elif !defined(WOLFCOSE_LEAN) && !defined(WOLFCOSE_NO_MAC)
    #define WOLFCOSE_MAC_WANT
#endif
#if defined(WOLFCOSE_MAC_WANT) && defined(WOLFCOSE_HAVE_MAC)
    #define WOLFCOSE_MAC
    #ifndef WOLFCOSE_NO_MAC_CREATE
        #define WOLFCOSE_MAC_CREATE
    #endif
    #ifndef WOLFCOSE_NO_MAC_VERIFY
        #define WOLFCOSE_MAC_VERIFY
    #endif
#endif

/* ----- Recipient key distribution (COSE_Encrypt / COSE_Mac only) ----- */

/* AES key wrap — extension */
#if defined(WOLFCOSE_ENABLE_AESWRAP)
    #ifndef HAVE_AES_KEYWRAP
        #error "WOLFCOSE_ENABLE_AESWRAP requires wolfSSL HAVE_AES_KEYWRAP"
    #endif
    #define WOLFCOSE_WANT_KEY_WRAP
#elif !defined(WOLFCOSE_LEAN) && !defined(WOLFCOSE_NO_AESWRAP) && \
      defined(HAVE_AES_KEYWRAP)
    #define WOLFCOSE_WANT_KEY_WRAP
#endif
#if defined(WOLFCOSE_WANT_KEY_WRAP) && \
    (defined(WOLFCOSE_ENCRYPT) || defined(WOLFCOSE_MAC)) && \
    !defined(WOLFCOSE_NO_RECIPIENTS) && \
    (LIBWOLFSSL_VERSION_HEX < 0x05009000)
    #error "wolfCOSE AES Key Wrap requires wolfSSL 5.9.0 or later"
#endif

/* ECDH-ES — extension */
#if defined(WOLFCOSE_ENABLE_ECDH_ES)
    #if !defined(HAVE_ECC) || !defined(HAVE_HKDF)
        #error "WOLFCOSE_ENABLE_ECDH_ES requires wolfSSL HAVE_ECC + HAVE_HKDF"
    #endif
    #define WOLFCOSE_WANT_ECDH
#elif !defined(WOLFCOSE_LEAN) && !defined(WOLFCOSE_NO_ECDH_ES) && \
      defined(HAVE_ECC) && defined(HAVE_HKDF)
    #define WOLFCOSE_WANT_ECDH
#endif

#if (defined(WOLFCOSE_ENCRYPT) || defined(WOLFCOSE_MAC)) && \
    !defined(WOLFCOSE_NO_RECIPIENTS)
    #define WOLFCOSE_RECIPIENTS
    #ifdef WOLFCOSE_WANT_KEY_WRAP
        #define WOLFCOSE_KEY_WRAP
    #endif
    #ifdef WOLFCOSE_WANT_ECDH
        #define WOLFCOSE_ECDH
        #if defined(HAVE_ECC) && defined(HAVE_HKDF)
            #define WOLFCOSE_ECDH_ES_DIRECT
        #endif
        #ifdef WOLFCOSE_KEY_WRAP
            #define WOLFCOSE_ECDH_WRAP
        #endif
    #endif
#endif

/* ----- COSE-HPKE (draft-ietf-cose-hpke-26) -----
 *
 * HPKE is deliberately opt-in in every build.  The P0 implementation supports
 * only the draft's HPKE-0 ciphersuite: DHKEM(P-256, HKDF-SHA256),
 * HKDF-SHA256, and AES-128-GCM in base mode.  Each wire operation has a
 * separate enable gate so send-only and receive-only targets do not carry the
 * other direction.  The two convenience switches enable both directions for
 * their respective COSE construction.
 */
#if (defined(WOLFCOSE_ENABLE_HPKE_0) || \
     defined(WOLFCOSE_ENABLE_HPKE_0_KE) || \
     defined(WOLFCOSE_ENABLE_HPKE_0_ENCRYPT) || \
     defined(WOLFCOSE_ENABLE_HPKE_0_DECRYPT) || \
     defined(WOLFCOSE_ENABLE_HPKE_0_KE_ENCRYPT) || \
     defined(WOLFCOSE_ENABLE_HPKE_0_KE_DECRYPT)) && \
    !defined(WOLFCOSE_EXPERIMENTAL)
    #error "COSE-HPKE selects experimental draft code (spec not yet a finalized RFC); also define WOLFCOSE_EXPERIMENTAL to acknowledge"
#endif

#if defined(WOLFCOSE_ENABLE_HPKE_0)
    #if defined(WOLFCOSE_NO_HPKE_0)
        #error "WOLFCOSE_ENABLE_HPKE_0 conflicts with WOLFCOSE_NO_HPKE_0"
    #endif
    #if !defined(WOLFCOSE_NO_HPKE_0_ENCRYPT)
        #define WOLFCOSE_ENABLE_HPKE_0_ENCRYPT
    #endif
    #if !defined(WOLFCOSE_NO_HPKE_0_DECRYPT)
        #define WOLFCOSE_ENABLE_HPKE_0_DECRYPT
    #endif
#endif

#if defined(WOLFCOSE_ENABLE_HPKE_0_KE)
    #if defined(WOLFCOSE_NO_HPKE_0)
        #error "WOLFCOSE_ENABLE_HPKE_0_KE conflicts with WOLFCOSE_NO_HPKE_0"
    #endif
    #if !defined(WOLFCOSE_NO_HPKE_0_KE_ENCRYPT)
        #define WOLFCOSE_ENABLE_HPKE_0_KE_ENCRYPT
    #endif
    #if !defined(WOLFCOSE_NO_HPKE_0_KE_DECRYPT)
        #define WOLFCOSE_ENABLE_HPKE_0_KE_DECRYPT
    #endif
#endif

#if defined(WOLFCOSE_NO_HPKE_0) && \
    (defined(WOLFCOSE_ENABLE_HPKE_0_ENCRYPT) || \
     defined(WOLFCOSE_ENABLE_HPKE_0_DECRYPT) || \
     defined(WOLFCOSE_ENABLE_HPKE_0_KE_ENCRYPT) || \
     defined(WOLFCOSE_ENABLE_HPKE_0_KE_DECRYPT))
    #error "WOLFCOSE_NO_HPKE_0 conflicts with an HPKE-0 operation enable"
#endif

#if (defined(WOLFCOSE_ENABLE_HPKE_0_ENCRYPT) && \
     defined(WOLFCOSE_NO_HPKE_0_ENCRYPT)) || \
    (defined(WOLFCOSE_ENABLE_HPKE_0_DECRYPT) && \
     defined(WOLFCOSE_NO_HPKE_0_DECRYPT)) || \
    (defined(WOLFCOSE_ENABLE_HPKE_0_KE_ENCRYPT) && \
     defined(WOLFCOSE_NO_HPKE_0_KE_ENCRYPT)) || \
    (defined(WOLFCOSE_ENABLE_HPKE_0_KE_DECRYPT) && \
     defined(WOLFCOSE_NO_HPKE_0_KE_DECRYPT))
    #error "An HPKE-0 operation cannot be both enabled and disabled"
#endif

#if defined(WOLFCOSE_ENABLE_HPKE_0_ENCRYPT) || \
    defined(WOLFCOSE_ENABLE_HPKE_0_DECRYPT) || \
    defined(WOLFCOSE_ENABLE_HPKE_0_KE_ENCRYPT) || \
    defined(WOLFCOSE_ENABLE_HPKE_0_KE_DECRYPT)
    #if !defined(HAVE_HPKE) || !defined(HAVE_ECC) || \
        !defined(HAVE_AESGCM) || defined(NO_SHA256) || \
        (defined(NO_ECC256) && !defined(HAVE_ALL_CURVES))
        #error "HPKE-0 requires wolfSSL HAVE_HPKE, HAVE_ECC, P-256, SHA-256, and HAVE_AESGCM"
    #endif
    #define WOLFCOSE_HAVE_HPKE_0
#endif

#if defined(WOLFCOSE_ENABLE_HPKE_0_ENCRYPT)
    #if !defined(WOLFCOSE_ENCRYPT0_ENCRYPT)
        #error "WOLFCOSE_ENABLE_HPKE_0_ENCRYPT requires COSE_Encrypt0 encrypt"
    #endif
    #define WOLFCOSE_HPKE_0_ENCRYPT
#endif

#if defined(WOLFCOSE_ENABLE_HPKE_0_DECRYPT)
    #if !defined(WOLFCOSE_ENCRYPT0_DECRYPT)
        #error "WOLFCOSE_ENABLE_HPKE_0_DECRYPT requires COSE_Encrypt0 decrypt"
    #endif
    #define WOLFCOSE_HPKE_0_DECRYPT
#endif

#if defined(WOLFCOSE_ENABLE_HPKE_0_KE_ENCRYPT)
    #if !defined(WOLFCOSE_ENCRYPT_ENCRYPT) || !defined(WOLFCOSE_RECIPIENTS)
        #error "WOLFCOSE_ENABLE_HPKE_0_KE_ENCRYPT requires COSE_Encrypt recipients and encrypt"
    #endif
    #define WOLFCOSE_HPKE_0_KE_ENCRYPT
#endif

#if defined(WOLFCOSE_ENABLE_HPKE_0_KE_DECRYPT)
    #if !defined(WOLFCOSE_ENCRYPT_DECRYPT) || !defined(WOLFCOSE_RECIPIENTS)
        #error "WOLFCOSE_ENABLE_HPKE_0_KE_DECRYPT requires COSE_Encrypt recipients and decrypt"
    #endif
    #define WOLFCOSE_HPKE_0_KE_DECRYPT
#endif

/* ----- COSE_Key serialization — core ----- */
#ifndef WOLFCOSE_NO_KEY_ENCODE
    #define WOLFCOSE_KEY_ENCODE
#endif
#ifndef WOLFCOSE_NO_KEY_DECODE
    #define WOLFCOSE_KEY_DECODE
#endif

/* ----- CBOR layer -----
 * Encode is required by any sign/encrypt/MAC-create op and by COSE_Key encode;
 * decode by any verify/decrypt/MAC-verify op and COSE_Key decode. On by
 * default; fail loud if explicitly disabled while still required. */
#if !defined(WOLFCOSE_NO_CBOR_ENCODE)
    #define WOLFCOSE_CBOR_ENCODE
#elif defined(WOLFCOSE_SIGN1_SIGN) || defined(WOLFCOSE_ENCRYPT0_ENCRYPT) || \
      defined(WOLFCOSE_MAC0_CREATE) || defined(WOLFCOSE_SIGN_SIGN) || \
      defined(WOLFCOSE_ENCRYPT_ENCRYPT) || defined(WOLFCOSE_MAC_CREATE) || \
      defined(WOLFCOSE_KEY_ENCODE)
    #error "WOLFCOSE_NO_CBOR_ENCODE conflicts with an enabled encode operation"
#endif
#if !defined(WOLFCOSE_NO_CBOR_DECODE)
    #define WOLFCOSE_CBOR_DECODE
#elif defined(WOLFCOSE_SIGN1_VERIFY) || defined(WOLFCOSE_ENCRYPT0_DECRYPT) || \
      defined(WOLFCOSE_MAC0_VERIFY) || defined(WOLFCOSE_SIGN_VERIFY) || \
      defined(WOLFCOSE_ENCRYPT_DECRYPT) || defined(WOLFCOSE_MAC_VERIFY) || \
      defined(WOLFCOSE_KEY_DECODE)
    #error "WOLFCOSE_NO_CBOR_DECODE conflicts with an enabled decode operation"
#endif

/* ----- Configurable limits (precedence: -D > WOLFCOSE_MIN_BUFFERS > default) -----
 * Floors track the largest enabled signature algorithm. See docs/Macros.md. */
#ifndef WOLFCOSE_MAX_SCRATCH_SZ
    #if defined(WOLFCOSE_HAVE_MLDSA)
        #define WOLFCOSE_MAX_SCRATCH_SZ      8192u
    #else
        #define WOLFCOSE_MAX_SCRATCH_SZ      512u
    #endif
#endif
#ifndef WOLFCOSE_MAX_SIG_SZ
    #if defined(WOLFCOSE_HAVE_MLDSA)
        #define WOLFCOSE_MAX_SIG_SZ  4627u
    #elif defined(WOLFCOSE_HAVE_RSAPSS)
        #define WOLFCOSE_MAX_SIG_SZ  512u
    #else
        #define WOLFCOSE_MAX_SIG_SZ  132u
    #endif
#endif
#ifndef WOLFCOSE_PROTECTED_HDR_MAX
    #define WOLFCOSE_PROTECTED_HDR_MAX    64u
#endif
#ifndef WOLFCOSE_CBOR_MAX_DEPTH
    #if defined(WOLFCOSE_MIN_BUFFERS)
        #define WOLFCOSE_CBOR_MAX_DEPTH    6u
    #else
        #define WOLFCOSE_CBOR_MAX_DEPTH    8u
    #endif
#endif
#ifndef WOLFCOSE_MAX_MAP_ITEMS
    #if defined(WOLFCOSE_MIN_BUFFERS)
        #if defined(WOLFCOSE_HAVE_RSAPSS)
            /* Full private RSA key = 11 entries
             * (kty,n,e,d,p,q,dP,dQ,qInv,kid,alg) per RFC 8230. */
            #define WOLFCOSE_MAX_MAP_ITEMS    11u
        #else
            #define WOLFCOSE_MAX_MAP_ITEMS    8u
        #endif
    #else
        #define WOLFCOSE_MAX_MAP_ITEMS    16u
    #endif
#endif

/* Floor checks: an override below the structural minimum is a build error. */
#if WOLFCOSE_MAX_SIG_SZ < 132u
    #error "WOLFCOSE_MAX_SIG_SZ below 132 cannot hold an ES256/EdDSA signature"
#endif
#if WOLFCOSE_MAX_SCRATCH_SZ < 256u
    #error "WOLFCOSE_MAX_SCRATCH_SZ below 256 is too small for COSE structures"
#endif
#if WOLFCOSE_CBOR_MAX_DEPTH < 4u
    #error "WOLFCOSE_CBOR_MAX_DEPTH below 4 cannot parse nested COSE messages"
#endif
#if WOLFCOSE_MAX_MAP_ITEMS < 4u
    #error "WOLFCOSE_MAX_MAP_ITEMS below 4 is too small for COSE headers"
#endif

#if defined(WOLFCOSE_HAVE_MLDSA) && (WOLFCOSE_MAX_SCRATCH_SZ < 4096u)
    #error "wolfCOSE: ML-DSA enabled but WOLFCOSE_MAX_SCRATCH_SZ too small"
#endif

#if defined(WOLFCOSE_EXT_SIGN) && !defined(WOLFCOSE_SIGN1_SIGN) && \
    !defined(WOLFCOSE_SIGN_SIGN)
    #error "WOLFCOSE_ENABLE_EXT_SIGN needs a signing op, which needs at least one local signature algorithm; the LEAN_VERIFY profiles are incompatible"
#endif

#ifdef __cplusplus
}
#endif

#endif /* WOLFCOSE_SETTINGS_H */
