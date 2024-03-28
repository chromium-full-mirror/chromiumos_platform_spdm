// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use spdm::types::code::{RequestCode, ResponseCode};
use spdm::types::error::{ErrorCode, SpdmResult};
use spdm_types::deps::Vendor;

use crate::{Responder, ResponderDeps};

///
/// VendorCommand request format:
///
/// | Byte offset | Size (bytes)    | Field               | Description                |
/// | :---------- | :-------------- | :------------------ | :------------------------- |
/// | 0           | 1               | SPDMVersion         | SPDM_THIS_VERSION          |
/// | 1           | 1               | RequestResponseCode | RequestCode::VendorCommand |
/// | 2           | 1               | Param1              | Reserved                   |
/// | 3           | 1               | Param2              | Reserved                   |
/// | 4           | N               | VendorMessage       |                            |
///
/// VendorCommand response format:
/// | Byte offset | Size (bytes) | Field               | Description                 |
/// | :---------- | :----------- | :------------------ | :-------------------------- |
/// | 0           | 1            | SPDMVersion         | SPDM_THIS_VERSION           |
/// | 1           | 1            | RequestResponseCode | ResponseCode::VendorCommand |
/// | 2           | 1            | Param1              | Reserved                    |
/// | 3           | 1            | Param2              | Reserved                    |
/// | 4           | N            | VendorMessage       |                             |
const VENDOR_COMMAND_HEADER_SIZE: usize = 4;
const VENDOR_COMMAND_CODE_OFFSET: usize = 1;

/// SessionEstablishedDispatcher handles the state where the session is successfully
/// established. Only vendor commands will be processed in this phase.
///
/// This trait is only used for separating impl blocks of `Responder` struct by functionality.
pub trait SessionEstablishedDispatcher {
    fn dispatch_request_session_established(
        &mut self,
        buf: &mut [u8],
        req_size: usize,
        req_code: RequestCode,
    ) -> SpdmResult<usize>;
}

/// VendorCommandDispatcher handles the VendorCommand request.
///
/// This trait is only used for separating impl blocks of `Responder` struct by functionality.
pub trait VendorCommandDispatcher {
    /// Handles the VendorCommand request and if successful, writes the VendorCommand response
    /// to `buf`.
    /// This is a custom command defined by this SPDM implementation. It basically carries arbitrary
    /// message that the responder knows how to handle and respond.
    fn dispatch_vendor_command_request(
        &mut self,
        buf: &mut [u8],
        req_size: usize,
    ) -> SpdmResult<usize>;
}

impl<D: ResponderDeps> VendorCommandDispatcher for Responder<D> {
    fn dispatch_vendor_command_request(
        &mut self,
        buf: &mut [u8],
        req_size: usize,
    ) -> SpdmResult<usize> {
        if req_size < VENDOR_COMMAND_HEADER_SIZE {
            return Err(ErrorCode::InvalidRequest);
        }
        let resp_size = self.vendor.process_vendor_request(
            &mut buf[VENDOR_COMMAND_HEADER_SIZE..],
            req_size - VENDOR_COMMAND_HEADER_SIZE,
        ) + VENDOR_COMMAND_HEADER_SIZE;
        buf[VENDOR_COMMAND_CODE_OFFSET] = ResponseCode::VendorCommand.0;
        Ok(resp_size)
    }
}

impl<D: ResponderDeps> SessionEstablishedDispatcher for Responder<D> {
    fn dispatch_request_session_established(
        &mut self,
        buf: &mut [u8],
        req_size: usize,
        req_code: RequestCode,
    ) -> SpdmResult<usize> {
        match req_code {
            RequestCode::VendorCommand => self.dispatch_vendor_command_request(buf, req_size),
            _ => Err(ErrorCode::UnexpectedRequest),
        }
    }
}

#[cfg(test)]
mod tests {
    use spdm::types::code::RequestCode;
    use spdm_test_deps::{TestIdentity, TestVendor};

    use super::*;
    use crate::test::TestResponderDeps;
    use crate::version::SPDM_THIS_VERSION;

    #[test]
    fn give_pub_key_request() {
        let mut buf = [
            SPDM_THIS_VERSION,
            RequestCode::VendorCommand.0,
            0,
            0,
            1,
            2,
            3,
            4,
        ];
        let req_size = 8;

        let mut spdm = Responder::<TestResponderDeps>::new(TestIdentity, TestVendor);

        let result = spdm.dispatch_vendor_command_request(&mut buf, req_size);
        assert_eq!(result, Ok(8));
    }
}
