# Makefile for wolfCOSE
#
# Copyright (C) 2026 wolfSSL Inc.
#
# Targets:
#   all           - Build libwolfcose.a (core library only)
#   shared        - Build libwolfcose.so
#   test          - Build + run unit tests
#   tool          - Build CLI tool (not part of core lib)
#   tool-test     - Automated round-trip: keygen -> sign -> verify
#   demo          - Build + run lifecycle demo
#   demos         - Build + run all basic demos
#   comprehensive - Build + run comprehensive algorithm tests (CI)
#   scenarios     - Build + run real-world scenario examples
#   pkg-config-test - Verify wolfSSL package discovery
#   clean         - Remove all build artifacts

CC       ?= gcc
AR       ?= ar
PKG_CONFIG ?= pkg-config
WOLFSSL_PACKAGE ?= wolfssl
WOLFSSL_PREFIX ?= /usr/local
WOLFSSL_PKG_CONFIG_FOUND := $(shell $(PKG_CONFIG) --exists \
    '$(WOLFSSL_PACKAGE)' 2>/dev/null && echo yes)

# Prefer package metadata so system installs do not need a hard-coded prefix.
# Explicit flags support custom installations and cross builds.
ifeq ($(WOLFSSL_PKG_CONFIG_FOUND),yes)
WOLFSSL_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags '$(WOLFSSL_PACKAGE)' 2>/dev/null)
WOLFSSL_LIBS   ?= $(shell $(PKG_CONFIG) --libs '$(WOLFSSL_PACKAGE)' 2>/dev/null)
else
WOLFSSL_CFLAGS ?= -isystem $(WOLFSSL_PREFIX)/include
WOLFSSL_LIBS   ?= -L$(WOLFSSL_PREFIX)/lib -lwolfssl
endif

CFLAGS    = -std=c99 -Os -Wall -Wextra -Wpedantic -Wshadow -Wconversion
CFLAGS   += -Wvla -Werror=vla
CFLAGS   += -ffunction-sections -fdata-sections
CFLAGS   += -fstack-usage
# Match wolfSSL's default (gnu11) struct ABI; -std=c99 alone disables
# HAVE_ANONYMOUS_INLINE_AGGREGATES and shrinks WC_RNG, corrupting the RNG.
CFLAGS   += -DHAVE_ANONYMOUS_INLINE_AGGREGATES=1
CFLAGS   += -I./include $(WOLFSSL_CFLAGS)
# Feature-matrix targets pass EXTRA_CFLAGS to recursive makes. GNU make does
# not append ordinary Makefile assignments to command-line CFLAGS, so make the
# opt-in flags survive CI's compiler-profile override as well.
override CFLAGS += $(EXTRA_CFLAGS)
LDFLAGS  ?=
LDLIBS   ?=
LDLIBS   += $(WOLFSSL_LIBS)

# Core library sources. The PSA/EAT translation unit is always present so
# config.h and user-settings feature gates cannot leave declared APIs without
# definitions. Its top-level gate produces no PSA/EAT code or symbols unless
# the caller explicitly enables WOLFCOSE_ENABLE_EAT_PSA.
CORE_SRC      = src/wolfcose_cbor.c src/wolfcose.c
EAT_PSA_SRC   = src/wolfcose_eat_psa.c
SRC           = $(CORE_SRC) $(EAT_PSA_SRC)
OBJ           = $(SRC:.c=.o)
LIB_A     = libwolfcose.a
LIB_SO    = libwolfcose.so
# Make cannot model variable values as dependencies. Compare a saved build
# configuration hash at parse time and force a core-object rebuild only when
# the effective compiler or wolfSSL configuration changes.
BUILD_CONFIG = .wolfcose-build-config
BUILD_CONFIG_VALUE := $(shell { \
    printf '%s\n' 'CC=$(CC)'; \
    printf '%s\n' 'CFLAGS=$(CFLAGS)'; \
    printf '%s\n' 'LDFLAGS=$(LDFLAGS)'; \
    printf '%s\n' 'LDLIBS=$(LDLIBS)'; \
    printf '%s\n' 'PKG_CONFIG=$(PKG_CONFIG)'; \
    printf '%s\n' 'WOLFSSL_PACKAGE=$(WOLFSSL_PACKAGE)'; \
    printf '%s\n' 'WOLFSSL_PREFIX=$(WOLFSSL_PREFIX)'; \
    printf '%s\n' 'WOLFSSL_CFLAGS=$(WOLFSSL_CFLAGS)'; \
    printf '%s\n' 'WOLFSSL_LIBS=$(WOLFSSL_LIBS)'; \
} | cksum)
BUILD_CONFIG_SAVED := $(shell test -f $(BUILD_CONFIG) && cat $(BUILD_CONFIG))
ifneq ($(strip $(BUILD_CONFIG_VALUE)),$(strip $(BUILD_CONFIG_SAVED)))
BUILD_CONFIG_CHANGED := FORCE
endif

# Tests (mirrors two-layer lib architecture)
TEST_SRC  = tests/test_cbor.c tests/test_cose.c tests/test_interop.c tests/test_eat_psa.c tests/test_eat_psa_profiles.c tests/test_main.c
TEST_BIN  = tests/test_wolfcose
EAT_PSA_TEST_BIN = tests/test_wolfcose_eat_psa
EAT_PSA_LIMITS_TEST_BIN = tests/test_wolfcose_eat_psa_limits

# Full PSA/EAT conformance test profile. Production integrations can select a
# smaller subset by defining only the WOLFCOSE_ENABLE_EAT_PSA_* switches they
# need; see docs/PSA-EAT.md. This variable is overridable for CI experiments.
EAT_PSA_FULL_FLAGS ?= -DWOLFCOSE_ENABLE_EAT_PSA \
	-DWOLFCOSE_ENABLE_EAT_PSA_CURRENT \
	-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1 -DWOLFCOSE_ENABLE_EAT_PSA_MAC0 \
	-DWOLFCOSE_ENABLE_EAT_PSA_ISSUE -DWOLFCOSE_ENABLE_EAT_PSA_LEGACY \
	-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1_ISSUE \
	-DWOLFCOSE_ENABLE_EAT_PSA_MAC0_ISSUE \
	-DWOLFCOSE_ENABLE_EAT_PSA_UEID_RESOLVER \
	-DWOLFCOSE_ENABLE_EAT_PSA_COMPONENT_ITERATOR

# Remove every lean-core decode path. Issuer-only matrix builds use this to
# prove that PSA/EAT claim and envelope creation do not retain CBOR decoding.
EAT_PSA_NO_DECODE_FLAGS = -DWOLFCOSE_NO_SIGN1_VERIFY \
	-DWOLFCOSE_NO_ENCRYPT0_DECRYPT -DWOLFCOSE_NO_MAC0_VERIFY \
	-DWOLFCOSE_NO_KEY_DECODE -DWOLFCOSE_NO_CBOR_DECODE

# Exercise established generic targets against an intentionally reduced
# algorithm set. PSA/EAT-specific targets select EAT_PSA_FULL_FLAGS instead.
REDUCED_ALG_FLAGS = -DWOLFCOSE_NO_ES384 -DWOLFCOSE_NO_ES512 \
	-DWOLFCOSE_NO_HMAC384 -DWOLFCOSE_NO_HMAC512

# Tools (compiled separately, never in core lib)
TOOL_SRC  = tools/wolfcose_tool.c
TOOL_BIN  = tools/wolfcose_tool

# Examples (compiled separately, never in core lib)
DEMO_SRC  = examples/lifecycle_demo.c
DEMO_BIN  = examples/lifecycle_demo
ENC_DEMO  = examples/encrypt0_demo
MAC_DEMO  = examples/mac0_demo
SIGN1_DEMO = examples/sign1_demo
LEANV_DEMO = examples/sign1_verify_lean
EAT_LEANV_DEMO = examples/psa_eat_verify_lean
EAT_DEMO   = examples/psa_eat_demo
MLDSA_DEMO  = examples/sign1_mldsa
EXTSIGN_DEMO = examples/ext_sign_demo
MLDSAV_DEMO = examples/sign1_verify_mldsa

# Comprehensive tests (CI)
COMP_SIGN     = examples/comprehensive/sign_all
COMP_ENCRYPT  = examples/comprehensive/encrypt_all
COMP_MAC      = examples/comprehensive/mac_all
COMP_ERRORS   = examples/comprehensive/errors_all

# Real-world scenarios
SCEN_FIRMWARE    = examples/scenarios/firmware_update
SCEN_MULTIPARTY  = examples/scenarios/multi_party_approval
SCEN_IOTFLEET    = examples/scenarios/iot_fleet_config
SCEN_SENSOR      = examples/scenarios/sensor_attestation
SCEN_BROADCAST   = examples/scenarios/group_broadcast_mac

.PHONY: all shared test pkg-config-test ecdsa-policy-test rsapss-policy-test zero-alloc-check zeroize-test ecc-import-policy-test ext-sign-test ext-sign-demo ext-sign-force-failure coverage eat-psa-test eat-psa-float-test eat-psa-min-buffers-test eat-psa-claim-limits-test eat-psa-profile-test eat-psa-config-check eat-psa-ext-sign-test eat-psa-ext-sign-force-failure eat-psa-coverage eat-psa-coverage-force-failure generic-reduced-alg-test tool tool-test cmdline-test demo demos lean-verify psa-eat-lean-verify psa-eat-demo mldsa-demo mldsa-verify comprehensive scenarios interop-tcose c99-check experimental-check clean FORCE

# --- Core library ---
all: $(LIB_A)

$(LIB_A): $(OBJ) $(BUILD_CONFIG_CHANGED)
	$(AR) rcs $@ $(OBJ)

FORCE:

$(BUILD_CONFIG): $(BUILD_CONFIG_CHANGED)
	@printf '%s\n' '$(BUILD_CONFIG_VALUE)' > $@.tmp
	@mv -f $@.tmp $@

shared: CFLAGS += -fPIC -DBUILDING_WOLFCOSE
shared: $(OBJ)
	$(CC) -shared -o $(LIB_SO) $(OBJ) $(LDFLAGS) $(LDLIBS)

src/%.o: src/%.c src/wolfcose_internal.h include/wolfcose/wolfcose.h $(BUILD_CONFIG_CHANGED) $(BUILD_CONFIG)
	$(CC) $(CFLAGS) -c $< -o $@

src/wolfcose_eat_psa.o: include/wolfcose/eat_psa.h

# --- Tests ---
# Keep this synthetic policy probe independent of profiles used by the build
# under test. It must exercise the local ECDSA Sign1 signing path even when the
# caller is testing a no-ECDSA or verify-only configuration.
ECDSA_POLICY_OPTS ?= -include wolfssl/options.h
ECDSA_POLICY_BASE_FLAGS = $(CFLAGS) -x c -fsyntax-only -Wno-error \
                          $(ECDSA_POLICY_OPTS) -DHAVE_ECC \
                          -UWOLFCOSE_ENABLE_DETERMINISTIC_ECDSA \
                          -UWOLFCOSE_NO_ES256 -UWOLFCOSE_NO_SIGN1 \
                          -UWOLFCOSE_NO_SIGN1_SIGN -UWOLFCOSE_LEAN_VERIFY \
                          -UWOLFCOSE_LEAN_VERIFY_MLDSA \
                          -UWOLFCOSE_LEAN_MLDSA
ECDSA_POLICY_NO_SUPPORT_FLAGS = $(CFLAGS) -x c -fsyntax-only -Wno-error \
                                -DWOLFSSL_NO_OPTIONS_H -DHAVE_ECC \
                                -UWOLFSSL_ECDSA_DETERMINISTIC_K \
                                -UWOLFSSL_ECDSA_DETERMINISTIC_K_VARIANT \
                                -UWOLFCOSE_NO_ES256 -UWOLFCOSE_NO_SIGN1 \
                                -UWOLFCOSE_NO_SIGN1_SIGN \
                                -UWOLFCOSE_LEAN_VERIFY \
                                -UWOLFCOSE_LEAN_VERIFY_MLDSA \
                                -UWOLFCOSE_LEAN_MLDSA
ECDSA_POLICY_FLAGS = $(ECDSA_POLICY_BASE_FLAGS) \
                     -DWOLFSSL_ECDSA_DETERMINISTIC_K \
                     -DWOLFCOSE_ENABLE_DETERMINISTIC_ECDSA
ECDSA_POLICY_HEADER = include/wolfcose/settings.h

ecdsa-policy-test:
	@set -e; \
	log_file=$$(mktemp "$${TMPDIR:-/tmp}/wolfcose-ecdsa.XXXXXX"); \
	trap 'rm -f "$$log_file"' 0 1 2 3 15; \
	if ! $(CC) $(ECDSA_POLICY_BASE_FLAGS) $(ECDSA_POLICY_HEADER) \
	        >"$$log_file" 2>&1; then \
	    cat "$$log_file"; \
	    echo "FAIL: default ECDSA policy rejected"; \
	    exit 1; \
	fi; \
	if $(CC) $(ECDSA_POLICY_NO_SUPPORT_FLAGS) \
	        -DWOLFCOSE_ENABLE_DETERMINISTIC_ECDSA \
	        $(ECDSA_POLICY_HEADER) >"$$log_file" 2>&1; then \
	    echo "FAIL: deterministic ECDSA accepted without wolfSSL support"; \
	    exit 1; \
	fi; \
	if ! grep -Fq \
	        "WOLFCOSE_ENABLE_DETERMINISTIC_ECDSA requires wolfSSL support" \
	        "$$log_file"; then \
	    cat "$$log_file"; \
	    echo "FAIL: deterministic ECDSA probe failed unexpectedly"; \
	    exit 1; \
	fi; \
	if ! $(CC) $(ECDSA_POLICY_FLAGS) $(ECDSA_POLICY_HEADER) \
	        >"$$log_file" 2>&1; then \
	    cat "$$log_file"; \
	    echo "FAIL: ECDSA policy probe environment unusable"; \
	    exit 1; \
	fi; \
	for backend in \
	    "-DWOLF_CRYPTO_CB -DWOLF_CRYPTO_CB_FIND" \
	    "-DWOLF_CRYPTO_CB -DWOLF_CRYPTO_CB_ONLY_ECC" \
	    "-DWOLFSSL_STM32_PKA" \
	    "-DWOLFSSL_ATECC508A" \
	    "-DWOLFSSL_ATECC608A" \
	    "-DWOLFSSL_MICROCHIP_TA100" \
	    "-DPLUTON_CRYPTO_ECC" \
	    "-DWOLFSSL_CRYPTOCELL" \
	    "-DWOLFSSL_SILABS_SE_ACCEL" \
	    "-DWOLFSSL_KCAPI_ECC" \
	    "-DWOLFSSL_SE050" \
	    "-DWOLFSSL_ASYNC_CRYPT -DWC_ASYNC_ENABLE_ECC -DHAVE_CAVIUM -DHAVE_CAVIUM_V" \
	    "-DWOLFSSL_ASYNC_CRYPT -DWC_ASYNC_ENABLE_ECC -DHAVE_INTEL_QA"; do \
	    if $(CC) $(ECDSA_POLICY_FLAGS) $$backend $(ECDSA_POLICY_HEADER) \
	            >"$$log_file" 2>&1; then \
	        echo "FAIL: unverified ECDSA backend accepted: $$backend"; \
	        exit 1; \
	    fi; \
	    if ! grep -Fq \
	            "ECDSA backend does not support deterministic signing" \
	            "$$log_file"; then \
	        cat "$$log_file"; \
	        echo "FAIL: ECDSA backend probe failed unexpectedly: $$backend"; \
	        exit 1; \
	    fi; \
	    if ! $(CC) $(ECDSA_POLICY_BASE_FLAGS) $$backend \
	            $(ECDSA_POLICY_HEADER) \
	            >"$$log_file" 2>&1; then \
	        cat "$$log_file"; \
	        echo "FAIL: default ECDSA backend rejected: $$backend"; \
	        exit 1; \
	    fi; \
	done; \
	if ! $(CC) $(ECDSA_POLICY_FLAGS) -DWOLFSSL_XILINX_CRYPT_VERSAL \
	        $(ECDSA_POLICY_HEADER) >"$$log_file" 2>&1; then \
	    cat "$$log_file"; \
	    echo "FAIL: deterministic Xilinx Versal ECDSA backend rejected"; \
	    exit 1; \
	fi; \
	if ! $(CC) $(ECDSA_POLICY_FLAGS) -DWOLFSSL_STM32_PKA \
	        -DWC_STM32_PKA_VERIFY_ONLY $(ECDSA_POLICY_HEADER) \
	        >"$$log_file" 2>&1; then \
	    cat "$$log_file"; \
	    echo "FAIL: STM32 PKA verify-only backend rejected"; \
	    exit 1; \
	fi; \
	if ! $(CC) $(ECDSA_POLICY_FLAGS) -DWOLF_CRYPTO_CB \
	        $(ECDSA_POLICY_HEADER) >"$$log_file" 2>&1; then \
	    cat "$$log_file"; \
	    echo "FAIL: software-fallback crypto callback rejected"; \
	    exit 1; \
	fi; \
	if ! $(CC) $(ECDSA_POLICY_FLAGS) -DWOLF_CRYPTO_CB \
	        -DWOLFCOSE_LEAN_VERIFY $(ECDSA_POLICY_HEADER) \
	        >"$$log_file" 2>&1; then \
	    cat "$$log_file"; \
	    echo "FAIL: ECDSA offload rejected in a verification-only build"; \
	    exit 1; \
	fi; \
	if ! $(CC) $(ECDSA_POLICY_FLAGS) -DWOLFSSL_SE050 \
	        -DWOLFSSL_SE050_ONLY_KEY_ID $(ECDSA_POLICY_HEADER) \
	        >"$$log_file" 2>&1; then \
	    cat "$$log_file"; \
	    echo "FAIL: deterministic ECDSA rejected for SE050 software keys"; \
	    exit 1; \
	fi; \
	echo "PASS: optional ECDSA nonce policy enforced"

rsapss-policy-test:
	$(CC) $(CFLAGS) -Werror=unused-function -fsyntax-only \
	    -DWOLFCOSE_NO_SIGN1 -DWOLFCOSE_NO_SIGN src/wolfcose.c
	$(CC) $(CFLAGS) -x c -fsyntax-only -DWOLFSSL_NO_OPTIONS_H -DWC_NO_HARDEN \
	    -DWC_RSA_PSS -DWOLFCOSE_NO_KEY_ENCODE \
	    -DWOLFCOSE_ENABLE_RSAPSS src/wolfcose.c
	$(CC) $(CFLAGS) -x c -fsyntax-only -DWOLFSSL_NO_OPTIONS_H -DWC_NO_HARDEN \
	    -DWC_RSA_PSS -DWOLFCOSE_LEAN_VERIFY \
	    -DWOLFCOSE_ENABLE_RSAPSS src/wolfcose.c
	@set -e; \
	log_file=$$(mktemp "$${TMPDIR:-/tmp}/wolfcose-rsapss.XXXXXX"); \
	trap 'rm -f "$$log_file"' 0 1 2 3 15; \
	if $(CC) $(CFLAGS) -x c -fsyntax-only -DWOLFSSL_NO_OPTIONS_H -DWC_NO_HARDEN \
	    -UHAVE_ECC -UWOLFSSL_EXPORT_INT \
	    -DWC_RSA_PSS -DWOLFCOSE_ENABLE_RSAPSS \
	    -DWOLFSSL_RSA_VERIFY_ONLY -DWOLFCOSE_LEAN_VERIFY \
	    src/wolfcose.c >"$$log_file" 2>&1; then \
	    echo "FAIL: unsupported RSA verify-only policy compiled"; \
	    exit 1; \
	fi; \
	grep -q "RSA-PSS key validation requires WOLFSSL_EXPORT_INT" \
	    "$$log_file"
	$(CC) $(CFLAGS) -x c -fsyntax-only -DWOLFSSL_NO_OPTIONS_H -DWC_NO_HARDEN \
	    -UHAVE_ECC -UWOLFSSL_EXPORT_INT \
	    -DWC_RSA_PSS -DWOLFCOSE_ENABLE_RSAPSS \
	    -DWOLFSSL_RSA_VERIFY_ONLY -DWOLFSSL_EXPORT_INT \
	    -DWOLFCOSE_LEAN_VERIFY src/wolfcose.c
	@set -e; \
	log_file=$$(mktemp "$${TMPDIR:-/tmp}/wolfcose-rsapss.XXXXXX"); \
	trap 'rm -f "$$log_file"' 0 1 2 3 15; \
	for backend in WOLF_CRYPTO_CB WOLFSSL_MICROCHIP_TA100; do \
	    if $(CC) $(CFLAGS) -x c -fsyntax-only -DWOLFSSL_NO_OPTIONS_H -DWC_NO_HARDEN \
	        -UHAVE_ECC -UWOLFSSL_EXPORT_INT \
	        -DWC_RSA_PSS -DWOLFCOSE_ENABLE_RSAPSS \
	        -DWOLFSSL_RSA_VERIFY_ONLY -D$$backend \
	        -DWOLFCOSE_LEAN_VERIFY include/wolfcose/settings.h \
	        >"$$log_file" 2>&1; then \
	        echo "FAIL: mixed RSA verify-only policy compiled: $$backend"; \
	        exit 1; \
	    fi; \
	    grep -q "RSA-PSS key validation requires WOLFSSL_EXPORT_INT" \
	        "$$log_file"; \
	done
	@echo "PASS: RSA-PSS operation guards compile cleanly"

zero-alloc-check:
	sh scripts/check_zero_alloc.sh

test: pkg-config-test ecdsa-policy-test rsapss-policy-test zero-alloc-check $(LIB_A)
	$(CC) $(CFLAGS) -o $(TEST_BIN) $(TEST_SRC) $(LIB_A) $(LDFLAGS) $(LDLIBS)
	./$(TEST_BIN)

pkg-config-test:
	sh scripts/test_pkg_config.sh

# PSA/EAT is intentionally absent from the default API. This target builds its
# complete feature profile directly from source, leaving `make test` a proof
# that an ordinary COSE build has no PSA/EAT API dependency.
eat-psa-test:
	$(CC) $(CFLAGS) $(EAT_PSA_FULL_FLAGS) -o $(EAT_PSA_TEST_BIN) \
		$(CORE_SRC) $(EAT_PSA_SRC) $(TEST_SRC) $(LDFLAGS) $(LDLIBS)
	./$(EAT_PSA_TEST_BIN)

# Exercise the optional float writers at runtime, including the decoder-mode
# safety checks shared by float and double encoders.
eat-psa-float-test:
	$(MAKE) clean
	$(MAKE) eat-psa-test EXTRA_CFLAGS='-DWOLFCOSE_FLOAT'

# Validate the current profile with WOLFCOSE_MIN_BUFFERS. The shared claim
# fixture includes every optional current claim, which proves the EAT parser
# does not inherit the smaller COSE-header map limit.
eat-psa-min-buffers-test:
	$(CC) $(CFLAGS) -DWOLFCOSE_MIN_BUFFERS $(EAT_PSA_FULL_FLAGS) \
		-o $(EAT_PSA_TEST_BIN) $(CORE_SRC) $(EAT_PSA_SRC) $(TEST_SRC) \
		$(LDFLAGS) $(LDLIBS)
	./$(EAT_PSA_TEST_BIN)

# Build a tiny, dedicated boundary test with floor-valid limits. It proves an
# exact claim/component map is accepted while each respective +1 declaration
# is rejected before the profile parser traverses attacker-controlled pairs.
eat-psa-claim-limits-test:
	$(MAKE) clean
	$(CC) $(CFLAGS) $(EAT_PSA_FULL_FLAGS) -DWOLFCOSE_TEST_EAT_PSA_LIMITS \
		-DWOLFCOSE_EAT_PSA_MAX_CLAIMS=10u \
		-DWOLFCOSE_EAT_PSA_MAX_COMPONENT_CLAIMS=5u \
		-o $(EAT_PSA_LIMITS_TEST_BIN) $(CORE_SRC) $(EAT_PSA_SRC) \
		tests/test_eat_psa_limits.c $(LDFLAGS) $(LDLIBS)
	./$(EAT_PSA_LIMITS_TEST_BIN)

# Prove selective configurations at runtime rather than merely compiling their
# source. The partial current attesters may issue #tfm with one enabled
# protection path, but their incomplete receivers must refuse that profile.
# Current/legacy namespace crossings are profile errors; a disabled envelope
# remains WOLFCOSE_E_UNSUPPORTED before crypto.
eat-psa-profile-test:
	$(MAKE) clean
	$(CC) $(CFLAGS) -DWOLFCOSE_TEST_EAT_PSA_PROFILES \
		-DWOLFCOSE_ENABLE_EAT_PSA -DWOLFCOSE_ENABLE_EAT_PSA_CURRENT \
		-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1 -DWOLFCOSE_ENABLE_EAT_PSA_ISSUE \
		-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1_ISSUE \
		-o $(EAT_PSA_TEST_BIN) $(CORE_SRC) $(EAT_PSA_SRC) \
		tests/test_eat_psa_profiles.c tests/test_eat_psa_profile_main.c \
		$(LDFLAGS) $(LDLIBS)
	./$(EAT_PSA_TEST_BIN)
	$(MAKE) clean
	$(CC) $(CFLAGS) -DWOLFCOSE_TEST_EAT_PSA_PROFILES \
		-DWOLFCOSE_ENABLE_EAT_PSA -DWOLFCOSE_ENABLE_EAT_PSA_CURRENT \
		-DWOLFCOSE_ENABLE_EAT_PSA_MAC0 -DWOLFCOSE_ENABLE_EAT_PSA_ISSUE \
		-DWOLFCOSE_ENABLE_EAT_PSA_MAC0_ISSUE \
		-o $(EAT_PSA_TEST_BIN) $(CORE_SRC) $(EAT_PSA_SRC) \
		tests/test_eat_psa_profiles.c tests/test_eat_psa_profile_main.c \
		$(LDFLAGS) $(LDLIBS)
	./$(EAT_PSA_TEST_BIN)
	$(MAKE) clean
	$(CC) $(CFLAGS) -DWOLFCOSE_TEST_EAT_PSA_PROFILES \
		-DWOLFCOSE_ENABLE_EAT_PSA -DWOLFCOSE_ENABLE_EAT_PSA_LEGACY \
		-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1 \
		-o $(EAT_PSA_TEST_BIN) $(CORE_SRC) $(EAT_PSA_SRC) \
		tests/test_eat_psa_profiles.c tests/test_eat_psa_profile_main.c \
		$(LDFLAGS) $(LDLIBS)
	./$(EAT_PSA_TEST_BIN)
	$(MAKE) clean
	$(CC) $(CFLAGS) -DWOLFCOSE_TEST_EAT_PSA_PROFILES \
		-DWOLFCOSE_ENABLE_EAT_PSA -DWOLFCOSE_ENABLE_EAT_PSA_LEGACY \
		-DWOLFCOSE_ENABLE_EAT_PSA_MAC0 \
		-o $(EAT_PSA_TEST_BIN) $(CORE_SRC) $(EAT_PSA_SRC) \
		tests/test_eat_psa_profiles.c tests/test_eat_psa_profile_main.c \
		$(LDFLAGS) $(LDLIBS)
	./$(EAT_PSA_TEST_BIN)

# Exercise the independently selectable PSA/EAT profiles, envelopes, and
# issuer helpers. This includes intentionally invalid switches so a typo or
# incomplete feature set fails at compile time rather than shipping a partial
# verifier. The regular full test target covers runtime behavior.
eat-psa-config-check:
	$(MAKE) clean
	$(MAKE) all
	@if nm $(LIB_A) | grep "wc_CoseEatPsaToken_" >/dev/null; then \
	    echo "FAIL: default library exports PSA/EAT"; exit 1; \
	fi
	@echo "PASS: default library has no PSA/EAT symbols"
	$(MAKE) test
	@echo "PASS: default generic verifiers reject private PSA/EAT decode flags"
	$(MAKE) test EXTRA_CFLAGS='-DWOLFCOSE_ENABLE_COSE_TEXT_LABELS'
	@echo "PASS: generic COSE text-label extension is independently selectable"
	$(MAKE) all EXTRA_CFLAGS='$(EAT_PSA_FULL_FLAGS)'
	@if ! nm $(LIB_A) | grep "wc_CoseEatPsaToken_Verify" >/dev/null; then \
	    echo "FAIL: enabled library omits PSA/EAT verifier"; exit 1; \
	fi
	$(MAKE) all
	@if nm $(LIB_A) | grep "wc_CoseEatPsaToken_" >/dev/null; then \
	    echo "FAIL: enabled-to-default build retained PSA/EAT symbols"; exit 1; \
	fi
	$(MAKE) all EXTRA_CFLAGS='-DHAVE_CONFIG_H -I./tests/config/eat_psa_config'
	@if ! nm $(LIB_A) | grep "wc_CoseEatPsaToken_Verify" >/dev/null; then \
	    echo "FAIL: config.h-enabled library omits PSA/EAT verifier"; exit 1; \
	fi
	$(MAKE) all
	@if nm $(LIB_A) | grep "wc_CoseEatPsaToken_" >/dev/null; then \
	    echo "FAIL: config.h-to-default build retained PSA/EAT symbols"; exit 1; \
	fi
	$(MAKE) all EXTRA_CFLAGS='-DWOLFCOSE_LEAN $(EAT_PSA_NO_DECODE_FLAGS) \
		-DWOLFCOSE_ENABLE_EAT_PSA -DWOLFCOSE_ENABLE_EAT_PSA_CURRENT \
		-DWOLFCOSE_ENABLE_EAT_PSA_ISSUE'
	@if ! nm $(LIB_A) | grep "wc_CoseEatPsaToken_EncodeClaims" >/dev/null; then \
	    echo "FAIL: claim-only issuer omits claim encoder"; exit 1; \
	fi
	@if nm $(LIB_A) | grep -E "wc_CoseEatPsaToken_(Verify|Create)" >/dev/null; then \
	    echo "FAIL: claim-only issuer contains a verifier or envelope creator"; exit 1; \
	fi
	$(MAKE) all EXTRA_CFLAGS='-DWOLFCOSE_LEAN $(EAT_PSA_NO_DECODE_FLAGS) \
		-DWOLFCOSE_ENABLE_EAT_PSA -DWOLFCOSE_ENABLE_EAT_PSA_CURRENT \
		-DWOLFCOSE_ENABLE_EAT_PSA_ISSUE \
		-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1_ISSUE'
	@if ! nm $(LIB_A) | grep "wc_CoseEatPsaToken_CreateSign1" >/dev/null; then \
	    echo "FAIL: Sign1-only issuer omits Sign1 creator"; exit 1; \
	fi
	@if nm $(LIB_A) | grep -E "wc_CoseEatPsaToken_(Verify|CreateMac0)" >/dev/null; then \
	    echo "FAIL: Sign1-only issuer contains verifier or Mac0 creator"; exit 1; \
	fi
	$(MAKE) all EXTRA_CFLAGS='-DWOLFCOSE_LEAN $(EAT_PSA_NO_DECODE_FLAGS) \
		-DWOLFCOSE_ENABLE_EAT_PSA -DWOLFCOSE_ENABLE_EAT_PSA_CURRENT \
		-DWOLFCOSE_ENABLE_EAT_PSA_ISSUE \
		-DWOLFCOSE_ENABLE_EAT_PSA_MAC0_ISSUE'
	@if ! nm $(LIB_A) | grep "wc_CoseEatPsaToken_CreateMac0" >/dev/null; then \
	    echo "FAIL: Mac0-only issuer omits Mac0 creator"; exit 1; \
	fi
	@if nm $(LIB_A) | grep -E "wc_CoseEatPsaToken_(Verify|CreateSign1)" >/dev/null; then \
	    echo "FAIL: Mac0-only issuer contains verifier or Sign1 creator"; exit 1; \
	fi
	$(MAKE) all
	$(CC) $(CFLAGS) -Werror -DWOLFCOSE_LEAN_VERIFY \
		-DWOLFCOSE_ENABLE_EAT_PSA -DWOLFCOSE_ENABLE_EAT_PSA_CURRENT \
		-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1 -fsyntax-only $(EAT_PSA_SRC)
	$(CC) $(CFLAGS) -Werror -DWOLFCOSE_LEAN \
		-DWOLFCOSE_ENABLE_EAT_PSA -DWOLFCOSE_ENABLE_EAT_PSA_CURRENT \
		-DWOLFCOSE_ENABLE_EAT_PSA_MAC0 -fsyntax-only $(EAT_PSA_SRC)
	$(CC) $(CFLAGS) -Werror -DWOLFCOSE_LEAN_VERIFY \
		-DWOLFCOSE_ENABLE_EAT_PSA -DWOLFCOSE_ENABLE_EAT_PSA_LEGACY \
		-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1 -fsyntax-only $(EAT_PSA_SRC)
	$(CC) $(CFLAGS) -Werror -DWOLFCOSE_LEAN \
		-DWOLFCOSE_ENABLE_EAT_PSA -DWOLFCOSE_ENABLE_EAT_PSA_LEGACY \
		-DWOLFCOSE_ENABLE_EAT_PSA_MAC0 -fsyntax-only $(EAT_PSA_SRC)
	$(CC) $(CFLAGS) -Werror \
		-DWOLFCOSE_ENABLE_EAT_PSA -DWOLFCOSE_ENABLE_EAT_PSA_CURRENT \
		-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1 -DWOLFCOSE_ENABLE_EAT_PSA_ISSUE \
		-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1_ISSUE \
		-DWOLFCOSE_NO_ES384 -DWOLFCOSE_NO_ES512 -fsyntax-only $(EAT_PSA_SRC)
	$(CC) $(CFLAGS) -Werror \
		-DWOLFCOSE_ENABLE_EAT_PSA -DWOLFCOSE_ENABLE_EAT_PSA_CURRENT \
		-DWOLFCOSE_ENABLE_EAT_PSA_MAC0 -DWOLFCOSE_ENABLE_EAT_PSA_ISSUE \
		-DWOLFCOSE_ENABLE_EAT_PSA_MAC0_ISSUE \
		-DWOLFCOSE_NO_HMAC384 -DWOLFCOSE_NO_HMAC512 -fsyntax-only $(EAT_PSA_SRC)
	$(CC) $(CFLAGS) -Werror -Werror=unused-function -DWOLFCOSE_LEAN \
		-DWOLFCOSE_NO_ES256 -DWOLFCOSE_ENABLE_ES384 \
		-DWOLFCOSE_NO_SIGN1_VERIFY -DWOLFCOSE_ENABLE_EAT_PSA \
		-DWOLFCOSE_ENABLE_EAT_PSA_CURRENT -DWOLFCOSE_ENABLE_EAT_PSA_ISSUE \
		-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1_ISSUE -fsyntax-only $(EAT_PSA_SRC)
	$(CC) $(CFLAGS) -Werror -Werror=unused-function -DWOLFCOSE_LEAN \
		-DWOLFCOSE_NO_ES256 -DWOLFCOSE_ENABLE_ES512 \
		-DWOLFCOSE_NO_SIGN1_VERIFY -DWOLFCOSE_ENABLE_EAT_PSA \
		-DWOLFCOSE_ENABLE_EAT_PSA_CURRENT -DWOLFCOSE_ENABLE_EAT_PSA_ISSUE \
		-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1_ISSUE -fsyntax-only $(EAT_PSA_SRC)
	$(CC) $(CFLAGS) -Werror -Werror=unused-function -DWOLFCOSE_LEAN \
		-DWOLFCOSE_NO_HMAC256 -DWOLFCOSE_ENABLE_HMAC384 \
		-DWOLFCOSE_NO_MAC0_VERIFY -DWOLFCOSE_ENABLE_EAT_PSA \
		-DWOLFCOSE_ENABLE_EAT_PSA_CURRENT -DWOLFCOSE_ENABLE_EAT_PSA_ISSUE \
		-DWOLFCOSE_ENABLE_EAT_PSA_MAC0_ISSUE -fsyntax-only $(EAT_PSA_SRC)
	$(CC) $(CFLAGS) -Werror -Werror=unused-function -DWOLFCOSE_LEAN \
		-DWOLFCOSE_NO_HMAC256 -DWOLFCOSE_ENABLE_HMAC512 \
		-DWOLFCOSE_NO_MAC0_VERIFY -DWOLFCOSE_ENABLE_EAT_PSA \
		-DWOLFCOSE_ENABLE_EAT_PSA_CURRENT -DWOLFCOSE_ENABLE_EAT_PSA_ISSUE \
		-DWOLFCOSE_ENABLE_EAT_PSA_MAC0_ISSUE -fsyntax-only $(EAT_PSA_SRC)
	$(CC) $(CFLAGS) -Werror -DWOLFSSL_USER_SETTINGS \
		-I./tests/config/eat_psa_curves \
		-DWOLFCOSE_ENABLE_EAT_PSA -DWOLFCOSE_ENABLE_EAT_PSA_CURRENT \
		-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1 -DWOLFCOSE_ENABLE_EAT_PSA_MAC0 \
		-fsyntax-only tests/test_eat_psa_curve_gates.c
	$(CC) $(CFLAGS) -Werror -DWOLFSSL_USER_SETTINGS \
		-I./tests/config/eat_psa_min_key -DECC_MIN_KEY_SZ=256 \
		-DWOLFCOSE_ENABLE_EAT_PSA -DWOLFCOSE_ENABLE_EAT_PSA_CURRENT \
		-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1 -DWOLFCOSE_ENABLE_EAT_PSA_MAC0 \
		-fsyntax-only tests/test_eat_psa_min_key_gates.c
	$(CC) $(CFLAGS) -Werror -DWOLFSSL_USER_SETTINGS \
		-I./tests/config/eat_psa_min_key -DECC_MIN_KEY_SZ=257 \
		-DWOLFCOSE_ENABLE_EAT_PSA -DWOLFCOSE_ENABLE_EAT_PSA_CURRENT \
		-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1 -DWOLFCOSE_ENABLE_EAT_PSA_MAC0 \
		-fsyntax-only tests/test_eat_psa_min_key_gates.c
	$(CC) $(CFLAGS) -Werror -DWOLFSSL_USER_SETTINGS \
		-I./tests/config/eat_psa_min_key -DECC_MIN_KEY_SZ=384 \
		-DWOLFCOSE_ENABLE_EAT_PSA -DWOLFCOSE_ENABLE_EAT_PSA_CURRENT \
		-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1 -DWOLFCOSE_ENABLE_EAT_PSA_MAC0 \
		-fsyntax-only tests/test_eat_psa_min_key_gates.c
	$(CC) $(CFLAGS) -Werror -DWOLFSSL_USER_SETTINGS \
		-I./tests/config/eat_psa_min_key -DECC_MIN_KEY_SZ=521 \
		-DWOLFCOSE_ENABLE_EAT_PSA -DWOLFCOSE_ENABLE_EAT_PSA_CURRENT \
		-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1 -DWOLFCOSE_ENABLE_EAT_PSA_MAC0 \
		-fsyntax-only tests/test_eat_psa_min_key_gates.c
	$(CC) $(CFLAGS) -Werror -DWOLFSSL_USER_SETTINGS \
		-I./tests/config/eat_psa_min_key -DECC_MIN_KEY_SZ=522 \
		-fsyntax-only tests/test_eat_psa_min_key_gates.c
	@if $(CC) $(CFLAGS) -DWOLFSSL_USER_SETTINGS \
		-I./tests/config/eat_psa_min_key -DECC_MIN_KEY_SZ=385 \
		-DWOLFCOSE_ENABLE_ES384 -fsyntax-only \
		tests/test_eat_psa_derived_gate.c >/dev/null 2>&1; then \
	    echo "FAIL: 385-bit minimum accepted explicit ES384"; exit 1; \
	fi
	@if $(CC) $(CFLAGS) -DWOLFSSL_USER_SETTINGS \
		-I./tests/config/eat_psa_min_key -DECC_MIN_KEY_SZ=522 \
		-DWOLFCOSE_ENABLE_ES512 -fsyntax-only \
		tests/test_eat_psa_derived_gate.c >/dev/null 2>&1; then \
	    echo "FAIL: 522-bit minimum accepted explicit ES512"; exit 1; \
	fi
	@if $(CC) $(CFLAGS) -DWOLFSSL_USER_SETTINGS \
		-I./tests/config/eat_psa_min_key -DECC_MIN_KEY_SZ=522 \
		-DWOLFCOSE_ENABLE_EAT_PSA -DWOLFCOSE_ENABLE_EAT_PSA_CURRENT \
		-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1 -fsyntax-only \
		tests/test_eat_psa_derived_gate.c >/dev/null 2>&1; then \
	    echo "FAIL: 522-bit minimum accepted PSA/EAT Sign1"; exit 1; \
	fi
	@if $(CC) $(CFLAGS) -DWOLFSSL_USER_SETTINGS \
		-I./tests/config/eat_psa_curves -DWOLFCOSE_ENABLE_ES384 \
		-fsyntax-only tests/test_eat_psa_curve_gates.c >/dev/null 2>&1; then \
	    echo "FAIL: P-256-only configuration accepted explicit ES384"; exit 1; \
	fi
	@if $(CC) $(CFLAGS) -DWOLFSSL_USER_SETTINGS \
		-I./tests/config/eat_psa_curves -DWOLFCOSE_ENABLE_ES512 \
		-fsyntax-only tests/test_eat_psa_curve_gates.c >/dev/null 2>&1; then \
	    echo "FAIL: P-256-only configuration accepted explicit ES512"; exit 1; \
	fi
	$(CC) $(CFLAGS) -Werror -DWOLFSSL_USER_SETTINGS \
		-I./tests/config/eat_psa_no_sha256 \
		-DWOLFCOSE_ENABLE_EAT_PSA -DWOLFCOSE_ENABLE_EAT_PSA_CURRENT \
		-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1 -DWOLFCOSE_ENABLE_EAT_PSA_MAC0 \
		-fsyntax-only tests/test_eat_psa_hash_gates.c
	@if $(CC) $(CFLAGS) -Werror \
		-DWOLFCOSE_ENABLE_EAT_PSA -DWOLFCOSE_ENABLE_EAT_PSA_CURRENT \
		-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1 -DWOLFCOSE_ENABLE_EAT_PSA_MAC0 \
		-DWOLFCOSE_NO_ES384 -DWOLFCOSE_NO_ES512 \
		-DWOLFCOSE_NO_HMAC384 -DWOLFCOSE_NO_HMAC512 \
		-DWOLFCOSE_EAT_PSA_TFM_FULL -fsyntax-only \
		tests/test_eat_psa_derived_gate.c >/dev/null 2>&1; then \
		    echo "FAIL: partial receiver accepted forced #tfm capability"; exit 1; \
	fi
	$(CC) $(CFLAGS) -Werror -DHAVE_ALL_CURVES -DNO_ECC256 \
		-DWOLFCOSE_ENABLE_EAT_PSA -DWOLFCOSE_ENABLE_EAT_PSA_CURRENT \
		-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1 -DWOLFCOSE_ENABLE_EAT_PSA_MAC0 \
		-DWOLFCOSE_TEST_NO_ECC256_ALL_CURVES -fsyntax-only \
		tests/test_eat_psa_derived_gate.c
	@if $(CC) $(CFLAGS) -DWOLFCOSE_ENABLE_EAT_PSA -fsyntax-only \
		$(EAT_PSA_SRC) >/dev/null 2>&1; then \
	    echo "FAIL: top-level PSA/EAT flag accepted without a profile/envelope"; exit 1; \
	fi
	@if $(CC) $(CFLAGS) -DWOLFCOSE_ENABLE_EAT_PSA_CURRENT -fsyntax-only \
		$(EAT_PSA_SRC) >/dev/null 2>&1; then \
	    echo "FAIL: current profile flag accepted without PSA/EAT"; exit 1; \
	fi
	@if $(CC) $(CFLAGS) -DWOLFCOSE_ENABLE_EAT_PSA_LEGACY -fsyntax-only \
		$(EAT_PSA_SRC) >/dev/null 2>&1; then \
	    echo "FAIL: legacy profile flag accepted without PSA/EAT"; exit 1; \
	fi
	@if $(CC) $(CFLAGS) -DWOLFCOSE_ENABLE_EAT_PSA_SIGN1 -fsyntax-only \
		$(EAT_PSA_SRC) >/dev/null 2>&1; then \
	    echo "FAIL: Sign1 flag accepted without PSA/EAT"; exit 1; \
	fi
	@if $(CC) $(CFLAGS) -DWOLFCOSE_ENABLE_EAT_PSA_MAC0 -fsyntax-only \
		$(EAT_PSA_SRC) >/dev/null 2>&1; then \
	    echo "FAIL: Mac0 flag accepted without PSA/EAT"; exit 1; \
	fi
	@if $(CC) $(CFLAGS) -DWOLFCOSE_ENABLE_EAT_PSA \
		-DWOLFCOSE_ENABLE_EAT_PSA_CURRENT -fsyntax-only \
		$(EAT_PSA_SRC) >/dev/null 2>&1; then \
	    echo "FAIL: PSA/EAT accepted a profile without an operation"; exit 1; \
	fi
	@if $(CC) $(CFLAGS) -DWOLFCOSE_ENABLE_EAT_PSA \
		-DWOLFCOSE_ENABLE_EAT_PSA_CURRENT \
		-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1_ISSUE -fsyntax-only \
		$(EAT_PSA_SRC) >/dev/null 2>&1; then \
	    echo "FAIL: Sign1 issuer accepted without common issuance"; exit 1; \
	fi
	@if $(CC) $(CFLAGS) -DWOLFCOSE_ENABLE_EAT_PSA \
		-DWOLFCOSE_ENABLE_EAT_PSA_CURRENT \
		-DWOLFCOSE_ENABLE_EAT_PSA_MAC0_ISSUE -fsyntax-only \
		$(EAT_PSA_SRC) >/dev/null 2>&1; then \
	    echo "FAIL: Mac0 issuer accepted without common issuance"; exit 1; \
	fi
	@if $(CC) $(CFLAGS) -DWOLFCOSE_ENABLE_EAT_PSA \
		-DWOLFCOSE_ENABLE_EAT_PSA_CURRENT -DWOLFCOSE_ENABLE_EAT_PSA_SIGN1 \
		-DWOLFCOSE_NO_ES256 -DWOLFCOSE_NO_ES384 -DWOLFCOSE_NO_ES512 \
		-fsyntax-only $(EAT_PSA_SRC) >/dev/null 2>&1; then \
	    echo "FAIL: Sign1 flag accepted without an ECDSA verifier"; exit 1; \
	fi
	@if $(CC) $(CFLAGS) -DWOLFCOSE_ENABLE_EAT_PSA \
		-DWOLFCOSE_ENABLE_EAT_PSA_CURRENT -DWOLFCOSE_ENABLE_EAT_PSA_MAC0 \
		-DNO_HMAC -fsyntax-only $(EAT_PSA_SRC) >/dev/null 2>&1; then \
	    echo "FAIL: Mac0 flag accepted without HMAC verification"; exit 1; \
	fi
	@if $(CC) $(CFLAGS) -DWOLFCOSE_ENABLE_EAT_PSA_UEID_RESOLVER -fsyntax-only \
		$(EAT_PSA_SRC) >/dev/null 2>&1; then \
	    echo "FAIL: UEID resolver flag accepted without PSA/EAT"; exit 1; \
	fi
	@if $(CC) $(CFLAGS) -DWOLFCOSE_ENABLE_EAT_PSA_COMPONENT_ITERATOR -fsyntax-only \
		$(EAT_PSA_SRC) >/dev/null 2>&1; then \
	    echo "FAIL: component iterator flag accepted without PSA/EAT"; exit 1; \
	fi
	@if $(CC) $(CFLAGS) -DWOLFCOSE_ENABLE_EAT_PSA \
		-DWOLFCOSE_ENABLE_EAT_PSA_CURRENT -DWOLFCOSE_ENABLE_EAT_PSA_ISSUE \
		-DWOLFCOSE_ENABLE_EAT_PSA_SIGN1_ISSUE -DWOLFCOSE_NO_SIGN1_SIGN \
		-fsyntax-only $(EAT_PSA_SRC) >/dev/null 2>&1; then \
	    echo "FAIL: Sign1 issuer accepted without a creation path"; exit 1; \
	fi
	@if $(CC) $(CFLAGS) -DWOLFCOSE_ENABLE_EAT_PSA \
		-DWOLFCOSE_ENABLE_EAT_PSA_CURRENT -DWOLFCOSE_ENABLE_EAT_PSA_ISSUE \
		-DWOLFCOSE_ENABLE_EAT_PSA_MAC0_ISSUE -DWOLFCOSE_NO_MAC0_CREATE \
		-fsyntax-only $(EAT_PSA_SRC) >/dev/null 2>&1; then \
	    echo "FAIL: Mac0 issuer accepted without a creation path"; exit 1; \
	fi
	@if $(CC) $(CFLAGS) -DWOLFCOSE_ENABLE_EAT_PSA \
		-DWOLFCOSE_ENABLE_EAT_PSA_LEGACY -DWOLFCOSE_ENABLE_EAT_PSA_SIGN1 \
		-DWOLFCOSE_ENABLE_EAT_PSA_ISSUE -fsyntax-only $(EAT_PSA_SRC) \
		>/dev/null 2>&1; then \
	    echo "FAIL: issuer flag accepted without current-profile support"; exit 1; \
	fi
	@if $(CC) $(CFLAGS) $(EAT_PSA_FULL_FLAGS) \
		-DWOLFCOSE_EAT_PSA_MAX_COMPONENTS=0u -fsyntax-only \
		$(EAT_PSA_SRC) >/dev/null 2>&1; then \
	    echo "FAIL: PSA/EAT accepted zero components"; exit 1; \
	fi
	@if $(CC) $(CFLAGS) $(EAT_PSA_FULL_FLAGS) \
		-DWOLFCOSE_EAT_PSA_MAX_CLAIMS=9u -fsyntax-only \
		$(EAT_PSA_SRC) >/dev/null 2>&1; then \
	    echo "FAIL: PSA/EAT accepted fewer than ten token claims"; exit 1; \
	fi
	@if $(CC) $(CFLAGS) $(EAT_PSA_FULL_FLAGS) \
		-DWOLFCOSE_EAT_PSA_MAX_COMPONENT_CLAIMS=4u -fsyntax-only \
		$(EAT_PSA_SRC) >/dev/null 2>&1; then \
	    echo "FAIL: PSA/EAT accepted fewer than five component claims"; exit 1; \
	fi
	@echo "PASS: PSA/EAT feature-gate matrix"

# --- Zeroize-hook test: asserts secret-scrubbing call sites actually run ---
zeroize-test:
	$(CC) $(CFLAGS) -DWOLFCOSE_TEST_ZEROIZE_HOOK -DWOLFCOSE_TEST_LOG_ENABLE \
	    -o $(TEST_BIN) $(SRC) $(TEST_SRC) $(LDFLAGS) $(LDLIBS)
	./$(TEST_BIN)

# --- ECC private-import backend policy ---
# Exercise the fail-closed path without requiring a hardware SDK/device.
ecc-import-policy-test:
	$(CC) $(CFLAGS) -DWOLFCOSE_FORCE_FAILURE \
	    -DWOLFCOSE_TEST_NONTRANSACTIONAL_ECC_IMPORT \
	    -o $(TEST_BIN) $(SRC) $(TEST_SRC) $(FORCE_FAIL_SRC) $(LDFLAGS) $(LDLIBS)
	./$(TEST_BIN)

# --- Delegated signing seam test: exercises the ext-sign callback ---
ext-sign-test:
	$(CC) $(CFLAGS) -DWOLFCOSE_ENABLE_EXT_SIGN \
	    -o $(TEST_BIN) $(SRC) $(TEST_SRC) $(LDFLAGS) $(LDLIBS)
	./$(TEST_BIN)

eat-psa-ext-sign-test:
	$(CC) $(CFLAGS) $(EAT_PSA_FULL_FLAGS) -DWOLFCOSE_ENABLE_EXT_SIGN \
	    -o $(TEST_BIN) $(SRC) $(TEST_SRC) $(LDFLAGS) $(LDLIBS)
	./$(TEST_BIN)

# --- Coverage ---
coverage: clean
	$(CC) $(CFLAGS) --coverage -fprofile-arcs -ftest-coverage -c src/wolfcose_cbor.c -o src/wolfcose_cbor.o
	$(CC) $(CFLAGS) --coverage -fprofile-arcs -ftest-coverage -c src/wolfcose.c -o src/wolfcose.o
	$(CC) $(CFLAGS) --coverage -fprofile-arcs -ftest-coverage -c src/wolfcose_eat_psa.c -o src/wolfcose_eat_psa.o
	$(AR) rcs $(LIB_A) $(OBJ)
	$(CC) $(CFLAGS) --coverage -fprofile-arcs -ftest-coverage -o $(TEST_BIN) $(TEST_SRC) $(LIB_A) $(LDFLAGS) $(LDLIBS)
	./$(TEST_BIN)
	gcov src/*.c

eat-psa-coverage: clean
	$(CC) $(CFLAGS) $(EAT_PSA_FULL_FLAGS) --coverage -fprofile-arcs -ftest-coverage -c src/wolfcose_cbor.c -o src/wolfcose_cbor.o
	$(CC) $(CFLAGS) $(EAT_PSA_FULL_FLAGS) --coverage -fprofile-arcs -ftest-coverage -c src/wolfcose.c -o src/wolfcose.o
	$(CC) $(CFLAGS) $(EAT_PSA_FULL_FLAGS) --coverage -fprofile-arcs -ftest-coverage -c src/wolfcose_eat_psa.c -o src/wolfcose_eat_psa.o
	$(AR) rcs $(LIB_A) $(CORE_SRC:.c=.o) $(EAT_PSA_SRC:.c=.o)
	$(CC) $(CFLAGS) $(EAT_PSA_FULL_FLAGS) --coverage -fprofile-arcs -ftest-coverage -o $(TEST_BIN) $(TEST_SRC) $(LIB_A) $(LDFLAGS) $(LDLIBS)
	./$(TEST_BIN)
	gcov src/*.c

# --- Coverage with forced failure injection (for testing error paths) ---
# See FORCE_FAILURE.md for documentation on this testing mechanism
FORCE_FAIL_SRC = tests/force_failure.c
coverage-force-failure: clean
	$(CC) $(CFLAGS) -DWOLFCOSE_FORCE_FAILURE --coverage -fprofile-arcs -ftest-coverage -c src/wolfcose_cbor.c -o src/wolfcose_cbor.o
	$(CC) $(CFLAGS) -DWOLFCOSE_FORCE_FAILURE --coverage -fprofile-arcs -ftest-coverage -c src/wolfcose.c -o src/wolfcose.o
	$(CC) $(CFLAGS) -DWOLFCOSE_FORCE_FAILURE --coverage -fprofile-arcs -ftest-coverage -c src/wolfcose_eat_psa.c -o src/wolfcose_eat_psa.o
	$(AR) rcs $(LIB_A) $(OBJ)
	$(CC) $(CFLAGS) -DWOLFCOSE_FORCE_FAILURE --coverage -fprofile-arcs -ftest-coverage -o $(TEST_BIN) $(TEST_SRC) $(FORCE_FAIL_SRC) $(LIB_A) $(LDFLAGS) $(LDLIBS)
	./$(TEST_BIN)
	gcov src/*.c

eat-psa-coverage-force-failure: clean
	$(CC) $(CFLAGS) $(EAT_PSA_FULL_FLAGS) -DWOLFCOSE_FORCE_FAILURE --coverage -fprofile-arcs -ftest-coverage -c src/wolfcose_cbor.c -o src/wolfcose_cbor.o
	$(CC) $(CFLAGS) $(EAT_PSA_FULL_FLAGS) -DWOLFCOSE_FORCE_FAILURE --coverage -fprofile-arcs -ftest-coverage -c src/wolfcose.c -o src/wolfcose.o
	$(CC) $(CFLAGS) $(EAT_PSA_FULL_FLAGS) -DWOLFCOSE_FORCE_FAILURE --coverage -fprofile-arcs -ftest-coverage -c src/wolfcose_eat_psa.c -o src/wolfcose_eat_psa.o
	$(AR) rcs $(LIB_A) $(CORE_SRC:.c=.o) $(EAT_PSA_SRC:.c=.o)
	$(CC) $(CFLAGS) $(EAT_PSA_FULL_FLAGS) -DWOLFCOSE_FORCE_FAILURE --coverage -fprofile-arcs -ftest-coverage -o $(TEST_BIN) $(TEST_SRC) $(FORCE_FAIL_SRC) $(LIB_A) $(LDFLAGS) $(LDLIBS)
	./$(TEST_BIN)
	gcov src/*.c

# --- Forced-failure coverage of the delegated seam ---
# WOLF_FAIL_EXT_SIGN lives behind both WOLFCOSE_FORCE_FAILURE and
# WOLFCOSE_ENABLE_EXT_SIGN, so it is unreachable unless both are set.
ext-sign-force-failure: clean
	$(CC) $(CFLAGS) -DWOLFCOSE_FORCE_FAILURE -DWOLFCOSE_ENABLE_EXT_SIGN \
	    -o $(TEST_BIN) $(SRC) $(TEST_SRC) $(FORCE_FAIL_SRC) $(LDFLAGS) $(LDLIBS)
	./$(TEST_BIN)

eat-psa-ext-sign-force-failure: clean
	$(CC) $(CFLAGS) $(EAT_PSA_FULL_FLAGS) -DWOLFCOSE_FORCE_FAILURE -DWOLFCOSE_ENABLE_EXT_SIGN \
	    -o $(TEST_BIN) $(SRC) $(TEST_SRC) $(FORCE_FAIL_SRC) $(LDFLAGS) $(LDLIBS)
	./$(TEST_BIN)

generic-reduced-alg-test:
	$(MAKE) clean
	$(MAKE) ext-sign-test EXTRA_CFLAGS='$(REDUCED_ALG_FLAGS)'
	$(MAKE) clean
	$(MAKE) coverage-force-failure EXTRA_CFLAGS='$(REDUCED_ALG_FLAGS)'

# --- CLI Tool (compiled out of core lib) ---
tool: $(LIB_A)
	$(CC) $(CFLAGS) -DWOLFCOSE_BUILD_TOOL -o $(TOOL_BIN) $(TOOL_SRC) $(LIB_A) $(LDFLAGS) $(LDLIBS)

# --- Round-trip proof: keygen -> sign -> verify in one command ---
tool-test: tool
	./$(TOOL_BIN) keygen -a ES256 -o /tmp/wolfcose_test.key
	echo "hello wolfCOSE" > /tmp/wolfcose_test.dat
	./$(TOOL_BIN) sign -k /tmp/wolfcose_test.key -a ES256 \
	    -i /tmp/wolfcose_test.dat -o /tmp/wolfcose_test.cose
	./$(TOOL_BIN) verify -k /tmp/wolfcose_test.key \
	    -i /tmp/wolfcose_test.cose
	@echo "PASS: round-trip sign/verify"

# --- Command-line tool test: every subcommand across all algorithms ---
cmdline-test: tool
	./scripts/cmdline-test.sh ./$(TOOL_BIN)

# --- Lifecycle demo ---
demo: $(LIB_A)
	$(CC) $(CFLAGS) -o $(DEMO_BIN) $(DEMO_SRC) $(LIB_A) $(LDFLAGS) $(LDLIBS)
	./$(DEMO_BIN)

# --- All demos ---
demos: $(LIB_A)
	$(CC) $(CFLAGS) -o $(DEMO_BIN) $(DEMO_SRC) $(LIB_A) $(LDFLAGS) $(LDLIBS)
	$(CC) $(CFLAGS) -o $(ENC_DEMO) examples/encrypt0_demo.c $(LIB_A) $(LDFLAGS) $(LDLIBS)
	$(CC) $(CFLAGS) -o $(MAC_DEMO) examples/mac0_demo.c $(LIB_A) $(LDFLAGS) $(LDLIBS)
	$(CC) $(CFLAGS) -o $(SIGN1_DEMO) examples/sign1_demo.c $(LIB_A) $(LDFLAGS) $(LDLIBS)
	@echo "=== Running all demos ==="
	./$(DEMO_BIN)
	./$(ENC_DEMO)
	./$(MAC_DEMO)
	./$(SIGN1_DEMO)

# --- Lean verify-only example (WOLFCOSE_LEAN_VERIFY) ---
# Compiles the wolfCOSE sources directly with the lean macro instead of the full
# prebuilt library, so the example exercises the minimal verify-only profile.
lean-verify:
	$(CC) $(CFLAGS) -DWOLFCOSE_LEAN_VERIFY -o $(LEANV_DEMO) \
		$(LEANV_DEMO).c src/wolfcose.c src/wolfcose_cbor.c $(LDFLAGS) $(LDLIBS)
	@echo "=== Running lean verify-only example ==="
	./$(LEANV_DEMO)

# --- Verify-only, full RFC 9783 #tfm PSA/EAT receiver ---
# A standardized #tfm receiver must retain both envelopes and all required
# algorithms. Issuance and optional PSA/EAT helpers remain compiled out.
psa-eat-lean-verify:
	$(CC) $(CFLAGS) -DWOLFCOSE_LEAN_VERIFY -DWOLFCOSE_ENABLE_EAT_PSA \
		-DWOLFCOSE_ENABLE_EAT_PSA_CURRENT -DWOLFCOSE_ENABLE_EAT_PSA_SIGN1 \
		-DWOLFCOSE_ENABLE_EAT_PSA_MAC0 -DWOLFCOSE_ENABLE_ES384 \
		-DWOLFCOSE_ENABLE_ES512 -DWOLFCOSE_ENABLE_HMAC384 \
		-DWOLFCOSE_ENABLE_HMAC512 \
		-o $(EAT_LEANV_DEMO) \
		$(EAT_LEANV_DEMO).c src/wolfcose.c src/wolfcose_cbor.c \
		src/wolfcose_eat_psa.c $(LDFLAGS) $(LDLIBS)
	@echo "=== Running verify-only full RFC 9783 PSA/EAT receiver ==="
	./$(EAT_LEANV_DEMO)

# --- RFC 9783 PSA/EAT device-onboarding example ---
psa-eat-demo:
	$(CC) $(CFLAGS) $(EAT_PSA_FULL_FLAGS) -o $(EAT_DEMO) \
		$(EAT_DEMO).c $(CORE_SRC) $(EAT_PSA_SRC) $(LDFLAGS) $(LDLIBS)
	@echo "=== Running RFC 9783 PSA/EAT device onboarding ==="
	./$(EAT_DEMO)

# --- Delegated signing example (WOLFCOSE_ENABLE_EXT_SIGN) ---
# Built from sources with the opt-in macro, since the prebuilt library does
# not carry the seam.
ext-sign-demo:
	$(CC) $(CFLAGS) -DWOLFCOSE_ENABLE_EXT_SIGN -o $(EXTSIGN_DEMO) \
		$(EXTSIGN_DEMO).c src/wolfcose.c src/wolfcose_cbor.c $(LDFLAGS) $(LDLIBS)
	@echo "=== Running delegated signing example ==="
	./$(EXTSIGN_DEMO)

# --- Post-quantum ML-DSA lean sign + verify (WOLFCOSE_LEAN_MLDSA) ---
# Requires wolfSSL built with ML-DSA (./configure --enable-dilithium).
mldsa-demo:
	$(CC) $(CFLAGS) -DWOLFCOSE_LEAN_MLDSA -o $(MLDSA_DEMO) \
		$(MLDSA_DEMO).c src/wolfcose.c src/wolfcose_cbor.c $(LDFLAGS) $(LDLIBS)
	@echo "=== Running ML-DSA sign + verify example ==="
	./$(MLDSA_DEMO)

# --- Smallest post-quantum verify-only (WOLFCOSE_LEAN_VERIFY_MLDSA) ---
mldsa-verify:
	$(CC) $(CFLAGS) -DWOLFCOSE_LEAN_VERIFY_MLDSA -o $(MLDSAV_DEMO) \
		$(MLDSAV_DEMO).c src/wolfcose.c src/wolfcose_cbor.c $(LDFLAGS) $(LDLIBS)
	@echo "=== Running lean ML-DSA verify-only example ==="
	./$(MLDSAV_DEMO)

# --- Comprehensive algorithm tests (CI) ---
comprehensive: $(LIB_A)
	@mkdir -p examples/comprehensive
	$(CC) $(CFLAGS) -o $(COMP_SIGN) examples/comprehensive/sign_all.c $(LIB_A) $(LDFLAGS) $(LDLIBS)
	$(CC) $(CFLAGS) -o $(COMP_ENCRYPT) examples/comprehensive/encrypt_all.c $(LIB_A) $(LDFLAGS) $(LDLIBS)
	$(CC) $(CFLAGS) -o $(COMP_MAC) examples/comprehensive/mac_all.c $(LIB_A) $(LDFLAGS) $(LDLIBS)
	$(CC) $(CFLAGS) -o $(COMP_ERRORS) examples/comprehensive/errors_all.c $(LIB_A) $(LDFLAGS) $(LDLIBS)
	@echo "=== Running comprehensive tests ==="
	./$(COMP_SIGN) || exit 1
	./$(COMP_ENCRYPT) || exit 1
	./$(COMP_MAC) || exit 1
	./$(COMP_ERRORS) || exit 1
	@echo "=== All comprehensive tests passed ==="

# --- Real-world scenario examples ---
scenarios: $(LIB_A)
	@mkdir -p examples/scenarios
	$(CC) $(CFLAGS) -o $(SCEN_FIRMWARE) examples/scenarios/firmware_update.c $(LIB_A) $(LDFLAGS) $(LDLIBS)
	$(CC) $(CFLAGS) -o $(SCEN_MULTIPARTY) examples/scenarios/multi_party_approval.c $(LIB_A) $(LDFLAGS) $(LDLIBS)
	$(CC) $(CFLAGS) -o $(SCEN_IOTFLEET) examples/scenarios/iot_fleet_config.c $(LIB_A) $(LDFLAGS) $(LDLIBS)
	$(CC) $(CFLAGS) -o $(SCEN_SENSOR) examples/scenarios/sensor_attestation.c $(LIB_A) $(LDFLAGS) $(LDLIBS)
	$(CC) $(CFLAGS) -o $(SCEN_BROADCAST) examples/scenarios/group_broadcast_mac.c $(LIB_A) $(LDFLAGS) $(LDLIBS)
	@echo "=== Running scenario examples ==="
	./$(SCEN_FIRMWARE) || exit 1
	./$(SCEN_MULTIPARTY) || exit 1
	./$(SCEN_IOTFLEET) || exit 1
	./$(SCEN_SENSOR) || exit 1
	./$(SCEN_BROADCAST) || exit 1
	@echo "=== All scenario examples passed ==="

# --- t_cose wire-interop (t_cose on OpenSSL; t_cose + QCBOR fetched at pinned SHAs) ---
# The harness TU never includes OpenSSL headers (they collide with wolfSSL on
# SHA256 etc.); the t_cose-side key loader is a separate TU. CI overrides
# TCOSE_CRYPTO_INC / TCOSE_CRYPTO_LIB per platform (system libssl on Linux).
TCOSE_DIR        ?= $(HOME)/interop-deps/t_cose
QCBOR_DIR        ?= $(HOME)/interop-deps/QCBOR
TCOSE_CRYPTO_INC ?=
TCOSE_CRYPTO_LIB ?= -lcrypto
INTEROP_DIR       = tests/interop/t_cose
INTEROP_BIN       = $(INTEROP_DIR)/interop_tcose
INTEROP_CFLAGS    = $(CFLAGS) -std=c99 -I$(TCOSE_DIR)/inc -I$(QCBOR_DIR)/inc

interop-tcose:
	$(CC) $(INTEROP_CFLAGS) $(EAT_PSA_FULL_FLAGS) -DT_COSE_USE_OPENSSL_CRYPTO -c $(INTEROP_DIR)/interop_tcose.c -o $(INTEROP_DIR)/interop_tcose.o
	$(CC) -std=c99 -Wall -Wextra -I$(TCOSE_DIR)/inc -I$(QCBOR_DIR)/inc $(TCOSE_CRYPTO_INC) \
	      -c $(INTEROP_DIR)/interop_key_ossl.c -o $(INTEROP_DIR)/interop_key.o
	$(CC) $(CFLAGS) $(EAT_PSA_FULL_FLAGS) -o $(INTEROP_BIN) $(CORE_SRC) $(EAT_PSA_SRC) \
	      $(INTEROP_DIR)/interop_tcose.o $(INTEROP_DIR)/interop_key.o \
	      $(TCOSE_DIR)/libt_cose.a $(QCBOR_DIR)/libqcbor.a \
	      $(TCOSE_CRYPTO_LIB) $(LDFLAGS) $(LDLIBS) -lm
	./$(INTEROP_BIN)

# --- C99 conformance gate ---
# Compiles every translation unit (core, tests, tool, examples) under strict
# ISO C99 with -pedantic-errors -Werror so any non-C99 construct fails the
# build. wolfSSL headers are -isystem so only wolfCOSE's own code is judged.
WOLFSSL_INC ?=
C99_SYSTEM_CFLAGS = $(foreach flag,$(WOLFSSL_CFLAGS),$(if $(filter -I%,$(flag)),-isystem $(patsubst -I%,%,$(flag)),$(flag)))
C99_WOLFSSL_CFLAGS = $(if $(strip $(WOLFSSL_INC)),-isystem $(WOLFSSL_INC),$(C99_SYSTEM_CFLAGS))
C99_FLAGS = -std=c99 -pedantic-errors -Werror -Wall -Wextra -Wshadow -Wconversion \
            -Wvla -DHAVE_ANONYMOUS_INLINE_AGGREGATES=1 \
            -I./include $(C99_WOLFSSL_CFLAGS) $(EXTRA_CFLAGS)
C99_SRC   = $(SRC) $(TEST_SRC) $(TOOL_SRC) $(DEMO_SRC) \
            $(ENC_DEMO).c $(MAC_DEMO).c $(SIGN1_DEMO).c \
            $(COMP_SIGN).c $(COMP_ENCRYPT).c $(COMP_MAC).c $(COMP_ERRORS).c \
            $(SCEN_FIRMWARE).c $(SCEN_MULTIPARTY).c $(SCEN_IOTFLEET).c \
            $(SCEN_SENSOR).c $(SCEN_BROADCAST).c $(EXTSIGN_DEMO).c
# Default features plus the opt-in paths (WOLFCOSE_FLOAT, delegated signing,
# and delegated signing without EdDSA), so the gate judges every
# conditionally-compiled translation unit, not just the default subset.
C99_CONFIGS = "" "-DWOLFCOSE_FLOAT" "-DWOLFCOSE_ENABLE_EXT_SIGN" \
    "-DWOLFCOSE_ENABLE_EXT_SIGN -DWOLFCOSE_NO_EDDSA -DWOLFCOSE_NO_ED448"

c99-check:
	@for cfg in $(C99_CONFIGS); do \
	    for f in $(C99_SRC); do \
	        echo "  C99 $$cfg $$f"; \
	        $(CC) $(C99_FLAGS) $$cfg -fsyntax-only $$f || exit 1; \
	    done; \
	done
	@$(CC) $(C99_FLAGS) -Werror=unused-function -Werror=unused-parameter \
	    -DNO_HMAC -DHAVE_AES_CBC -DWOLFCOSE_ENABLE_AESMAC \
	    -DWOLFCOSE_NO_RECIPIENTS -DWOLFCOSE_NO_ENCRYPT \
	    -fsyntax-only src/wolfcose.c
	@for cfg in "$(EAT_PSA_FULL_FLAGS)" "$(EAT_PSA_FULL_FLAGS) -DWOLFCOSE_ENABLE_EXT_SIGN"; do \
	    for f in src/wolfcose_eat_psa.c tests/test_eat_psa.c $(EAT_LEANV_DEMO).c $(EAT_DEMO).c; do \
	        echo "  C99 PSA/EAT $$cfg $$f"; \
	        $(CC) $(C99_FLAGS) $$cfg -fsyntax-only $$f || exit 1; \
	    done; \
	done
	$(CC) $(C99_FLAGS) $(EAT_PSA_FULL_FLAGS) -DWOLFCOSE_TEST_EAT_PSA_LIMITS \
		-DWOLFCOSE_EAT_PSA_MAX_CLAIMS=10u \
		-DWOLFCOSE_EAT_PSA_MAX_COMPONENT_CLAIMS=5u -fsyntax-only \
		tests/test_eat_psa_limits.c
	@echo "PASS: all sources conform to ISO C99 (-pedantic-errors)"

# Experimental-feature acknowledgement gate. Proves WOLFCOSE_EXPERIMENTAL guards
# draft (pre-RFC) features: enabling one without it is a hard error, enabling
# both compiles, and a normal build pulls in zero experimental code.
EXP_FLAGS = -std=c99 -pedantic-errors -I./include $(C99_WOLFSSL_CFLAGS) \
            -DHAVE_ANONYMOUS_INLINE_AGGREGATES=1 $(EXTRA_CFLAGS)
# Include settings.h plus one declaration so the stub is a valid C99 TU.
EXP_TU = printf '\#include <wolfcose/settings.h>\nint wolfcose_experimental_gate_check;\n'

experimental-check:
	@echo "  EXP feature without acknowledgement (expect error)"
	@if $(EXP_TU) | \
	    $(CC) $(EXP_FLAGS) -DWOLFCOSE_ENABLE_EXPERIMENTAL_EXAMPLE \
	    -fsyntax-only -x c - 2>experimental-check.err; then \
	    echo "FAIL: experimental feature compiled without WOLFCOSE_EXPERIMENTAL"; \
	    rm -f experimental-check.err; exit 1; \
	fi
	@grep -q WOLFCOSE_EXPERIMENTAL experimental-check.err || { \
	    echo "FAIL: gate error did not mention WOLFCOSE_EXPERIMENTAL"; \
	    cat experimental-check.err; rm -f experimental-check.err; exit 1; }
	@rm -f experimental-check.err
	@echo "  EXP feature with acknowledgement (expect pass)"
	@$(EXP_TU) | \
	    $(CC) $(EXP_FLAGS) -DWOLFCOSE_ENABLE_EXPERIMENTAL_EXAMPLE \
	    -DWOLFCOSE_EXPERIMENTAL -fsyntax-only -x c -
	@echo "  EXP normal build (expect pass, zero experimental code)"
	@$(EXP_TU) | \
	    $(CC) $(EXP_FLAGS) -fsyntax-only -x c -
	@echo "PASS: WOLFCOSE_EXPERIMENTAL gate enforced"

# --- Cleanup ---
clean:
	rm -f $(OBJ) $(TEST_BIN) $(EAT_PSA_TEST_BIN) $(EAT_PSA_LIMITS_TEST_BIN) $(TOOL_BIN) $(DEMO_BIN) $(ENC_DEMO) $(MAC_DEMO) \
	    $(EXTSIGN_DEMO) $(SIGN1_DEMO) $(LEANV_DEMO) $(EAT_LEANV_DEMO) $(EAT_DEMO) $(COMP_SIGN) $(COMP_ENCRYPT) $(COMP_MAC) $(COMP_ERRORS) \
	    $(SCEN_FIRMWARE) $(SCEN_MULTIPARTY) $(SCEN_IOTFLEET) $(SCEN_SENSOR) $(SCEN_BROADCAST) \
	    $(INTEROP_DIR)/*.o $(INTEROP_DIR)/*.su $(INTEROP_BIN) \
	    $(LIB_A) $(LIB_SO) $(BUILD_CONFIG) $(BUILD_CONFIG).tmp src/*.su tests/*.su examples/*.su examples/comprehensive/*.su examples/scenarios/*.su \
	    src/*.gcno src/*.gcda tests/*.gcno tests/*.gcda *.gcov experimental-check.err
	rm -rf tests/*.dSYM tools/*.dSYM examples/*.dSYM \
	    examples/comprehensive/*.dSYM examples/scenarios/*.dSYM
