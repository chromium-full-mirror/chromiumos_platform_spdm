// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use spdm_test_deps::{TestCrypto, TestDispatch, TestIdentity};

use crate::RequesterDeps;

pub struct TestRequesterDeps;

impl RequesterDeps for TestRequesterDeps {
    type Crypto = TestCrypto;
    type Identity = TestIdentity;
    type Dispatch = TestDispatch;
}
