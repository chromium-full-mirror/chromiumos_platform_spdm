# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

CC?=cc

TARGET?=target/debug
TEST_PATH:=spdm_test.out
TEST_FULL_PATH:=$(TARGET)/$(TEST_PATH)

test: $(TEST_FULL_PATH)
	$(TEST_FULL_PATH)

$(TARGET)/libspdm.a:
	cargo build

$(TEST_FULL_PATH): $(TARGET)/libspdm.a
	$(CC) spdm_test.c -L$(TARGET) -lspdm $(TARGET)/libspdm.a -o $(TEST_FULL_PATH)

.PHONY: $(TEST_FULL_PATH)

clean:
	cargo clean
