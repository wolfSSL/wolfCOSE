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
#   clean         - Remove all build artifacts

CC       ?= gcc
AR       ?= ar
CFLAGS    = -std=c11 -Os -Wall -Wextra -Wpedantic -Wshadow -Wconversion
CFLAGS   += $(shell pkg-config --cflags wolfssl 2>/dev/null || echo "-I/usr/local/include")
CFLAGS   += -fstack-usage
CFLAGS   += -I./include -I/usr/local/include
CFLAGS   += $(EXTRA_CFLAGS)
LDFLAGS   = -L/usr/local/lib -lwolfssl
LDFLAGS   += $(shell pkg-config --libs wolfssl 2>/dev/null || echo "-L/usr/local/lib -lwolfssl") 

# Core library sources (only these go into .a/.so)
SRC       = src/wolfcose_cbor.c src/wolfcose.c
OBJ       = $(SRC:.c=.o)
LIB_A     = libwolfcose.a
LIB_SO    = libwolfcose.so

# Tests (mirrors two-layer lib architecture)
TEST_SRC  = tests/test_cbor.c tests/test_cose.c tests/test_interop.c tests/test_main.c
TEST_BIN  = tests/test_wolfcose

# Tools (compiled separately, never in core lib)
TOOL_SRC  = tools/wolfcose_tool.c
TOOL_BIN  = tools/wolfcose_tool

# Examples (compiled separately, never in core lib)
DEMO_SRC  = examples/lifecycle_demo.c
DEMO_BIN  = examples/lifecycle_demo
ENC_DEMO  = examples/encrypt0_demo
MAC_DEMO  = examples/mac0_demo
SIGN1_DEMO = examples/sign1_demo

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

.PHONY: all shared test coverage tool tool-test demo demos comprehensive scenarios clean

# --- Core library ---
all: $(LIB_A)

$(LIB_A): $(OBJ)
	$(AR) rcs $@ $^

shared: CFLAGS += -fPIC -DBUILDING_WOLFCOSE
shared: $(OBJ)
	$(CC) -shared -o $(LIB_SO) $(OBJ) $(LDFLAGS)

src/%.o: src/%.c src/wolfcose_internal.h include/wolfcose/wolfcose.h
	$(CC) $(CFLAGS) -c $< -o $@

# --- Tests ---
test: $(LIB_A)
	$(CC) $(CFLAGS) -o $(TEST_BIN) $(TEST_SRC) $(LIB_A) $(LDFLAGS)
	./$(TEST_BIN)

# --- Coverage ---
coverage: clean
	$(CC) $(CFLAGS) --coverage -fprofile-arcs -ftest-coverage -c src/wolfcose_cbor.c -o src/wolfcose_cbor.o
	$(CC) $(CFLAGS) --coverage -fprofile-arcs -ftest-coverage -c src/wolfcose.c -o src/wolfcose.o
	$(AR) rcs $(LIB_A) $(OBJ)
	$(CC) $(CFLAGS) --coverage -fprofile-arcs -ftest-coverage -o $(TEST_BIN) $(TEST_SRC) $(LIB_A) $(LDFLAGS)
	./$(TEST_BIN)
	gcov src/*.c

# --- Coverage with forced failure injection (for testing error paths) ---
# See FORCE_FAILURE.md for documentation on this testing mechanism
FORCE_FAIL_SRC = tests/force_failure.c
coverage-force-failure: clean
	$(CC) $(CFLAGS) -DWOLFCOSE_FORCE_FAILURE --coverage -fprofile-arcs -ftest-coverage -c src/wolfcose_cbor.c -o src/wolfcose_cbor.o
	$(CC) $(CFLAGS) -DWOLFCOSE_FORCE_FAILURE --coverage -fprofile-arcs -ftest-coverage -c src/wolfcose.c -o src/wolfcose.o
	$(AR) rcs $(LIB_A) $(OBJ)
	$(CC) $(CFLAGS) -DWOLFCOSE_FORCE_FAILURE --coverage -fprofile-arcs -ftest-coverage -o $(TEST_BIN) $(TEST_SRC) $(FORCE_FAIL_SRC) $(LIB_A) $(LDFLAGS)
	./$(TEST_BIN)
	gcov src/*.c

# --- CLI Tool (compiled out of core lib) ---
tool: $(LIB_A)
	$(CC) $(CFLAGS) -DWOLFCOSE_BUILD_TOOL -o $(TOOL_BIN) $(TOOL_SRC) $(LIB_A) $(LDFLAGS)

# --- Round-trip proof: keygen -> sign -> verify in one command ---
tool-test: tool
	./$(TOOL_BIN) keygen -a ES256 -o /tmp/wolfcose_test.key
	echo "hello wolfCOSE" > /tmp/wolfcose_test.dat
	./$(TOOL_BIN) sign -k /tmp/wolfcose_test.key -a ES256 \
	    -i /tmp/wolfcose_test.dat -o /tmp/wolfcose_test.cose
	./$(TOOL_BIN) verify -k /tmp/wolfcose_test.key \
	    -i /tmp/wolfcose_test.cose
	@echo "PASS: round-trip sign/verify"

# --- Lifecycle demo ---
demo: $(LIB_A)
	$(CC) $(CFLAGS) -o $(DEMO_BIN) $(DEMO_SRC) $(LIB_A) $(LDFLAGS)
	./$(DEMO_BIN)

# --- All demos ---
demos: $(LIB_A)
	$(CC) $(CFLAGS) -o $(DEMO_BIN) $(DEMO_SRC) $(LIB_A) $(LDFLAGS)
	$(CC) $(CFLAGS) -o $(ENC_DEMO) examples/encrypt0_demo.c $(LIB_A) $(LDFLAGS)
	$(CC) $(CFLAGS) -o $(MAC_DEMO) examples/mac0_demo.c $(LIB_A) $(LDFLAGS)
	$(CC) $(CFLAGS) -o $(SIGN1_DEMO) examples/sign1_demo.c $(LIB_A) $(LDFLAGS)
	@echo "=== Running all demos ==="
	./$(DEMO_BIN)
	./$(ENC_DEMO)
	./$(MAC_DEMO)
	./$(SIGN1_DEMO)

# --- Comprehensive algorithm tests (CI) ---
comprehensive: $(LIB_A)
	@mkdir -p examples/comprehensive
	$(CC) $(CFLAGS) -o $(COMP_SIGN) examples/comprehensive/sign_all.c $(LIB_A) $(LDFLAGS)
	$(CC) $(CFLAGS) -o $(COMP_ENCRYPT) examples/comprehensive/encrypt_all.c $(LIB_A) $(LDFLAGS)
	$(CC) $(CFLAGS) -o $(COMP_MAC) examples/comprehensive/mac_all.c $(LIB_A) $(LDFLAGS)
	$(CC) $(CFLAGS) -o $(COMP_ERRORS) examples/comprehensive/errors_all.c $(LIB_A) $(LDFLAGS)
	@echo "=== Running comprehensive tests ==="
	./$(COMP_SIGN) || exit 1
	./$(COMP_ENCRYPT) || exit 1
	./$(COMP_MAC) || exit 1
	./$(COMP_ERRORS) || exit 1
	@echo "=== All comprehensive tests passed ==="

# --- Real-world scenario examples ---
scenarios: $(LIB_A)
	@mkdir -p examples/scenarios
	$(CC) $(CFLAGS) -o $(SCEN_FIRMWARE) examples/scenarios/firmware_update.c $(LIB_A) $(LDFLAGS)
	$(CC) $(CFLAGS) -o $(SCEN_MULTIPARTY) examples/scenarios/multi_party_approval.c $(LIB_A) $(LDFLAGS)
	$(CC) $(CFLAGS) -o $(SCEN_IOTFLEET) examples/scenarios/iot_fleet_config.c $(LIB_A) $(LDFLAGS)
	$(CC) $(CFLAGS) -o $(SCEN_SENSOR) examples/scenarios/sensor_attestation.c $(LIB_A) $(LDFLAGS)
	$(CC) $(CFLAGS) -o $(SCEN_BROADCAST) examples/scenarios/group_broadcast_mac.c $(LIB_A) $(LDFLAGS)
	@echo "=== Running scenario examples ==="
	./$(SCEN_FIRMWARE) || exit 1
	./$(SCEN_MULTIPARTY) || exit 1
	./$(SCEN_IOTFLEET) || exit 1
	./$(SCEN_SENSOR) || exit 1
	./$(SCEN_BROADCAST) || exit 1
	@echo "=== All scenario examples passed ==="

# --- Cleanup ---
clean:
	rm -f $(OBJ) $(TEST_BIN) $(TOOL_BIN) $(DEMO_BIN) $(ENC_DEMO) $(MAC_DEMO) \
	    $(SIGN1_DEMO) $(COMP_SIGN) $(COMP_ENCRYPT) $(COMP_MAC) $(COMP_ERRORS) \
	    $(SCEN_FIRMWARE) $(SCEN_MULTIPARTY) $(SCEN_IOTFLEET) $(SCEN_SENSOR) $(SCEN_BROADCAST) \
	    $(LIB_A) $(LIB_SO) src/*.su tests/*.su examples/comprehensive/*.su examples/scenarios/*.su \
	    src/*.gcno src/*.gcda tests/*.gcno tests/*.gcda *.gcov
