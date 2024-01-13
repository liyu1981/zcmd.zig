#!/bin/bash
KCOV=../kcov/zig-out/bin/kcov
TEST_BIN_BASE=./zig-out/bin/zcmd_kcov_test

rm -rf ./cov/*

zig test -femit-bin=${TEST_BIN_BASE}1 src/zcmd.zig
${KCOV} ./cov --include-path=$(pwd) ${TEST_BIN_BASE}1

zig test -femit-bin=${TEST_BIN_BASE}2 src/panicTest.zig --test-filter "catchers"
${KCOV} ./cov --include-path=$(pwd) ${TEST_BIN_BASE}2

zig test -femit-bin=${TEST_BIN_BASE}3 src/panicTest.zig --test-filter "runCommandAndGetResult no binary panics trigger"
${KCOV} ./cov --include-path=$(pwd) ${TEST_BIN_BASE}3
