// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use spdm::types::code::{RequestCode, ResponseCode};
use spdm::types::error::{ErrorCode, SpdmResult};
use spdm::types::message::GivePubKeyRequest;
use spdm_types::deps::Identity;

use super::internal::ResponderState;
use crate::{Responder, ResponderDeps};

/// WaitForRequesterKeyDispatcher handles the state where the responder is waiting
/// for the requester to provide their public key. After processing GivePubKey
/// request successfully, the state handler should advance to the next state.
///
/// This trait is only used for separating impl blocks of `Responder` struct by functionality.
pub trait WaitForRequesterKeyDispatcher {
    fn dispatch_request_wait_for_requester_key(
        &mut self,
        buf: &mut [u8],
        req_size: usize,
        req_code: RequestCode,
    ) -> SpdmResult<usize>;
}

/// GivePubKeyDispatcher handles the GivePubKey request.
///
/// This trait is only used for separating impl blocks of `Responder` struct by functionality.
pub trait GivePubKeyDispatcher {
    /// Handles the GivePubKey request and if successful, writes the GivePubKey response to `buf`.
    ///
    /// GivePubKey request format:
    ///
    /// | Byte offset | Size (bytes)    | Field               | Description              |
    /// | :---------- | :-------------- | :------------------ | :----------------------- |
    /// | 0           | 1               | SPDMVersion         | SPDM_THIS_VERSION        |
    /// | 1           | 1               | RequestResponseCode | RequestCode::GivePubKey  |
    /// | 2           | 1               | Param1              | Reserved                 |
    /// | 3           | 1               | Param2              | Reserved                 |
    /// | 4           | PUBLIC_KEY_SIZE | PublicKey           | Public Key               |
    ///
    /// GivePubKey response format:
    /// | Byte offset | Size (bytes) | Field               | Description             |
    /// | :---------- | :----------- | :------------------ | :---------------------- |
    /// | 0           | 1            | SPDMVersion         | SPDM_THIS_VERSION       |
    /// | 1           | 1            | RequestResponseCode | Response::GivePubKey    |
    /// | 2           | 1            | Param1              | Reserved                |
    /// | 3           | 1            | Param2              | Reserved                |
    fn dispatch_give_pub_key_request(
        &mut self,
        buf: &mut [u8],
        req_size: usize,
    ) -> SpdmResult<usize>;
}

impl<D: ResponderDeps> GivePubKeyDispatcher for Responder<D> {
    fn dispatch_give_pub_key_request(
        &mut self,
        buf: &mut [u8],
        req_size: usize,
    ) -> SpdmResult<usize> {
        if req_size != GivePubKeyRequest::SIZE {
            return Err(ErrorCode::InvalidRequest);
        }
        let request: &GivePubKeyRequest = (&buf[..req_size])
            .try_into()
            .map_err(|_| ErrorCode::Unspecified)?;

        if !D::Identity::is_public_key_valid(&request.public_key) {
            return Err(ErrorCode::InvalidRequest);
        }

        self.session.set_requester_public_key(&request.public_key);
        buf[1] = ResponseCode::GivePubKey.0;

        // Advance state.
        self.state = ResponderState::WaitForFinish;
        Ok(4)
    }
}

impl<D: ResponderDeps> WaitForRequesterKeyDispatcher for Responder<D> {
    fn dispatch_request_wait_for_requester_key(
        &mut self,
        buf: &mut [u8],
        req_size: usize,
        req_code: RequestCode,
    ) -> SpdmResult<usize> {
        match req_code {
            RequestCode::GivePubKey => self.dispatch_give_pub_key_request(buf, req_size),
            _ => Err(ErrorCode::UnexpectedRequest),
        }
    }
}

#[cfg(test)]
mod tests {
    use spdm::types::code::RequestCode;
    use spdm_test_deps::{TestIdentity, TestVendor, TEST_IDENTITY_PUBLIC_KEY};
    use zerocopy::AsBytes;

    use super::*;
    use crate::dispatch::internal::ResponderState;
    use crate::test::TestResponderDeps;
    use crate::version::SPDM_THIS_VERSION;

    #[test]
    fn give_pub_key_request() {
        let mut buf = vec![SPDM_THIS_VERSION, RequestCode::GivePubKey.0, 0, 0];
        buf.extend_from_slice(TEST_IDENTITY_PUBLIC_KEY.as_bytes());
        let req_size = GivePubKeyRequest::SIZE;

        let mut spdm = Responder::<TestResponderDeps>::new(TestIdentity, TestVendor);

        let result = spdm.dispatch_give_pub_key_request(&mut buf, req_size);
        assert_eq!(result, Ok(4));
        assert!(spdm.session.requester_public_key.is_some());
        assert!(matches!(spdm.state, ResponderState::WaitForFinish));
    }

    #[cfg(feature = "mock")]
    mod mock {
        use mocktopus::mocking::{MockContext, MockResult};

        use super::*;

        #[test]
        fn give_pub_key_request_invalid_key() {
            let mut buf = vec![SPDM_THIS_VERSION, RequestCode::GivePubKey.0, 0, 0];
            buf.extend_from_slice(TEST_IDENTITY_PUBLIC_KEY.as_bytes());
            let req_size = GivePubKeyRequest::SIZE;

            MockContext::new()
                .mock_safe(TestIdentity::is_public_key_valid, |key| {
                    assert_eq!(key.as_bytes(), TEST_IDENTITY_PUBLIC_KEY.as_bytes());
                    MockResult::Return(false)
                })
                .run(|| {
                    let mut spdm = Responder::<TestResponderDeps>::new(TestIdentity, TestVendor);
                    spdm.state = ResponderState::WaitForRequesterKey;

                    let result = spdm.dispatch_give_pub_key_request(&mut buf, req_size);
                    assert_eq!(result, Err(ErrorCode::InvalidRequest));
                    assert!(matches!(spdm.state, ResponderState::WaitForRequesterKey));
                });
        }
    }
}
