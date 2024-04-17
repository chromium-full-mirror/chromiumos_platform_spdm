// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg(feature = "mock")]
use mocktopus::macros::*;
use spdm_types::deps::Dispatch;
use uninit::out_ref::Out;

pub struct TestDispatch;

#[cfg_attr(feature = "mock", mockable)]
impl Dispatch for TestDispatch {
    fn dispatch_request<'a>(
        &mut self,
        _is_secure: bool,
        _buf: Out<'a, [u8]>,
        _req_size: usize,
    ) -> &'a mut [u8] {
        &mut []
    }
}
