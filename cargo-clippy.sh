#!/bin/sh

# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

cargo clippy --workspace --no-default-features --target thumbv7m-none-eabi\
  --exclude spdm_requester -- -D warnings
cargo clippy --workspace --all-targets -- -D warnings
