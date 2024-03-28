// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use spdm::types::code::{RequestCode, ResponseCode};
use spdm::types::error::{ErrorCode, SpdmResult};
use spdm::types::message::FinishRequest;
use zerocopy::AsBytes;

use super::internal::ResponderState;
use crate::session::ResponderSession;
use crate::{Responder, ResponderDeps};

/// WaitForFinishDispatcher handles the state where the responder is waiting
/// for the requester to send the Finish request. After processing Finish
/// request successfully, the session is successfully established.
///
/// This trait is only used for separating impl blocks of `Responder` struct by functionality.
pub trait WaitForFinishDispatcher {
    fn dispatch_request_wait_for_finish(
        &mut self,
        buf: &mut [u8],
        req_size: usize,
        req_code: RequestCode,
    ) -> SpdmResult<usize>;
}

/// FinishDispatcher handles the Finish request.
///
/// This trait is only used for separating impl blocks of `Responder` struct by functionality.
pub trait FinishDispatcher {
    /// Handles the Finish request and if successful, writes the Finish response to `buf`.
    /// Finish request format: see `FinishRequest` struct.
    /// Finish response format:
    /// | Byte offset | Size (bytes) | Field               | Description         |
    /// | :---------- | :----------- | :------------------ | :------------------ |
    /// | 0           | 1            | SPDMVersion         | SPDM_THIS_VERSION   |
    /// | 1           | 1            | RequestResponseCode | RequestCode::Finish |
    /// | 2           | 1            | Param1              | Reserved            |
    /// | 3           | 1            | Param2              | Reserved            |
    fn dispatch_finish_request(&mut self, buf: &mut [u8], req_size: usize) -> SpdmResult<usize>;
}

impl<D: ResponderDeps> FinishDispatcher for Responder<D> {
    fn dispatch_finish_request(&mut self, buf: &mut [u8], req_size: usize) -> SpdmResult<usize> {
        if req_size != FinishRequest::SIZE {
            return Err(ErrorCode::InvalidRequest);
        }
        let request: &FinishRequest = (&buf[..req_size])
            .try_into()
            .map_err(|_| ErrorCode::Unspecified)?;

        self.session.extend_transcript_hash_with_finish_request(
            &request.as_bytes()[..FinishRequest::PARTIAL_SIZE],
        )?;
        self.session.verify_finish_message(&request.signature)?;
        self.session
            .validate_finish_message_hmac(&request.requester_verify_data)?;

        buf[1] = ResponseCode::Finish.0;
        buf[2] = 0;
        buf[3] = 0;

        // Advance state.
        self.state = ResponderState::SessionEstablished;
        Ok(4)
    }
}

impl<D: ResponderDeps> WaitForFinishDispatcher for Responder<D> {
    fn dispatch_request_wait_for_finish(
        &mut self,
        buf: &mut [u8],
        req_size: usize,
        req_code: RequestCode,
    ) -> SpdmResult<usize> {
        match req_code {
            RequestCode::Finish => self.dispatch_finish_request(buf, req_size),
            _ => Err(ErrorCode::UnexpectedRequest),
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "mock")]
    mod mock {
        use mocktopus::mocking::{MockResult, Mockable};
        use spdm::session::Session;
        use spdm_test_deps::{TestCrypto, TestIdentity, TestVendor};

        use super::super::*;
        use crate::session::ResponderSession;
        use crate::test::TestResponderDeps;

        #[test]
        fn finish_request() {
            let mut buf = [0; FinishRequest::SIZE];
            Session::<TestCrypto>::extend_transcript_hash_with_finish_request
                .mock_safe(|_, _| MockResult::Return(Ok(())));
            Session::<TestCrypto>::verify_finish_message
                .mock_safe(|_, _| MockResult::Return(Ok(())));
            Session::<TestCrypto>::validate_finish_message_hmac
                .mock_safe(|_, _| MockResult::Return(Ok(())));

            let mut spdm = Responder::<TestResponderDeps>::new(TestIdentity, TestVendor);
            let result = spdm.dispatch_finish_request(&mut buf, FinishRequest::SIZE);
            assert_eq!(result, Ok(4));
        }
    }
}
