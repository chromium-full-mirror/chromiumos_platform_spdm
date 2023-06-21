// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::crypto::TestCrypto;
use super::Identity;

pub struct TestIdentity;

impl Identity for TestIdentity {
    type Crypto = TestCrypto;
}
