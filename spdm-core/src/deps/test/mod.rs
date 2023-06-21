// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Stub dependencies used in tests.

mod crypto;
mod identity;

pub use crypto::*;
pub use identity::*;

use super::*;

pub struct SpdmTestDeps;

impl SpdmDeps for SpdmTestDeps {
    type Crypto = TestCrypto;
    type Identity = TestIdentity;
}
