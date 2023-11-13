// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/// Identity trait defines the interface to access the SPDM identity key pair.
pub trait Vendor {
    /// Processes the vendor request to the vendor request handler, and put the
    /// response back into `buf`, and return the response size.
    fn process_vendor_request(&self, buf: &mut [u8], req_size: usize) -> usize;
}
