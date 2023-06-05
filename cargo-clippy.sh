#!/bin/sh

# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

cargo clippy --no-default-features --target thumbv7m-none-eabi -- -D warnings
cargo clippy --all-targets -- -D warnings
