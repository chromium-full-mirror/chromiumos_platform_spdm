// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use spdm::types::code::ResponseCode;
use spdm::types::error::{ErrorCode, SpdmResult};
use spdm::types::message::{GET_VERSION_REQUEST_SIZE, VERSION_RESPONSE_SIZE};

use crate::version::{SPDM_THIS_ALPHA_VERSION, SPDM_THIS_VERSION};
use crate::{Responder, ResponderDeps};

/// GetVersionDispatcher handles the GetVersion request.
///
/// This trait is only used for separating impl blocks of `Responder` struct by functionality.
pub trait GetVersionDispatcher {
    /// Version response format:
    ///
    /// | Byte offset | Size (bytes) | Field               | Description             |
    /// | :---------- | :----------- | :------------------ | :---------------------- |
    /// | 0           | 1            | SPDMVersion         | 0x10                    |
    /// | 1           | 1            | RequestResponseCode | ResponseCode::Version   |
    /// | 2           | 3            | Reserved            |                         |
    /// | 5           | 1            | EntryCount          | 1                       |
    /// | 6           | 1            | Version             | SPDM_THIS_VERSION       |
    /// | 7           | 1            | AlphaVersion        | SPDM_THIS_ALPHA_VERSION |
    fn dispatch_get_version_request(
        &mut self,
        buf: &mut [u8],
        req_size: usize,
    ) -> SpdmResult<usize>;
}

impl<D: ResponderDeps> GetVersionDispatcher for Responder<D> {
    fn dispatch_get_version_request(
        &mut self,
        buf: &mut [u8],
        // All non-reserved fields have been checked by `parse_header` so we don't need to
        // read the request again.
        _req_size: usize,
    ) -> SpdmResult<usize> {
        if buf.len() < VERSION_RESPONSE_SIZE {
            return Err(ErrorCode::ResponseTooLarge);
        }

        // The copy is very cheap: the request is only 4 bytes.
        let get_version_request: [u8; GET_VERSION_REQUEST_SIZE] =
            buf[..GET_VERSION_REQUEST_SIZE].try_into().unwrap();

        // [0] is 0x10 as in the request, [2, 3] are reserved params as in the request.
        // They don't need to be set to a different value again.
        buf[1] = ResponseCode::Version.0;
        buf[4] = 0;
        buf[5] = 1;
        buf[6] = SPDM_THIS_VERSION;
        buf[7] = SPDM_THIS_ALPHA_VERSION;

        self.session.set_negotiation_transcript(
            get_version_request,
            buf[..VERSION_RESPONSE_SIZE].try_into().unwrap(),
        );

        Ok(VERSION_RESPONSE_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use spdm::types::code::RequestCode;
    use spdm_test_deps::{TestIdentity, TestVendor};

    use super::*;
    use crate::dispatch::internal::ResponderState;
    use crate::test::TestResponderDeps;

    #[test]
    fn get_version_request() {
        let mut buf = [0x10, RequestCode::GetVersion.0, 0, 0, 0, 0, 0, 0];
        let req_size = 4;

        let mut spdm = Responder::<TestResponderDeps>::new(TestIdentity, TestVendor);

        let result = spdm.dispatch_get_version_request(&mut buf, req_size);
        assert_eq!(result, Ok(8));
        assert_eq!(
            buf[..8],
            [
                0x10,
                ResponseCode::Version.0,
                0,
                0,
                0,
                1,
                SPDM_THIS_VERSION,
                SPDM_THIS_ALPHA_VERSION
            ]
        );
        assert_eq!(
            spdm.session.transcript,
            Some([
                0x10,
                RequestCode::GetVersion.0,
                0,
                0,
                0x10,
                ResponseCode::Version.0,
                0,
                0,
                0,
                1,
                SPDM_THIS_VERSION,
                SPDM_THIS_ALPHA_VERSION
            ])
        );
        assert!(matches!(spdm.state, ResponderState::WaitForKeyExchange));
    }
}
