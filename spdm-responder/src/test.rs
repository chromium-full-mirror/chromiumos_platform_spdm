// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use spdm_test_deps::{TestCrypto, TestIdentity, TestVendor};

use crate::ResponderDeps;

pub struct TestResponderDeps;

impl ResponderDeps for TestResponderDeps {
    type Crypto = TestCrypto;
    type Identity = TestIdentity;
    type Vendor = TestVendor;
}
