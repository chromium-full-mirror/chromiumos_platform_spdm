// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(feature = "mock")]
use mocktopus::macros::*;
use spdm_types::deps::Vendor;

pub struct TestVendor;

#[cfg_attr(feature = "mock", mockable)]
impl Vendor for TestVendor {
    fn process_vendor_request(&self, _buf: &mut [u8], req_size: usize) -> usize {
        req_size
    }
}
