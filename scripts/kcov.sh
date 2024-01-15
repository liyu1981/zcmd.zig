#!/bin/bash
KCOV=../kcov/zig-out/bin/kcov
TEST_BIN_BASE=./zig-out/bin/zcmd_kcov_test

rm -rf ./cov/*

zig test -femit-bin=${TEST_BIN_BASE}1 src/zcmd.zig
${KCOV} ./cov --include-path=$(pwd) ${TEST_BIN_BASE}1

# zig test -femit-bin=${TEST_BIN_BASE}2 src/panicTest.zig --test-filter "catchers"
# ${KCOV} ./cov --include-path=$(pwd) ${TEST_BIN_BASE}2

# FILTERS=(
#   'no binary panics trigger'
#   'exit with sigabrt'
#   'exit with not zero'
# )
# FILTERS_LEN=${#FILTERS[@]}

# for ((TEST_NUM=3; TEST_NUM<FILTERS_LEN+3; TEST_NUM++)); do
#   CURRENT_FILTER="${FILTERS[TEST_NUM - 3]}"  # Adjust index to start from 0
#   echo "expect panic from: runCommandAndGetResult ${CURRENT_FILTER}"
#   zig test -femit-bin="${TEST_BIN_BASE}${TEST_NUM}" src/panicTest.zig --test-filter "runCommandAndGetResult ${CURRENT_FILTER}"
#   ${KCOV} ./cov --include-path=$(pwd) "${TEST_BIN_BASE}${TEST_NUM}"
# done

echo "All tests done, coverage generated."
