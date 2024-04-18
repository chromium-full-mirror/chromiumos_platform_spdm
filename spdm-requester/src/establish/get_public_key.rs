// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use spdm::types::code::RequestCode;
use spdm::types::message::{GetPubKeyResponse, GET_PUBLIC_KEY_RESPONSE_SIZE};
use spdm_types::deps::{Dispatch, Identity};
use uninit::extension_traits::AsOut;
use uninit::uninit_array;

use crate::error::{RequesterError, RequesterStatus};
use crate::version::SPDM_THIS_VERSION;
use crate::{Requester, RequesterDeps};

/// GetPubKeySender sends the GetPubKey request.
///
/// This trait is only used for separating impl blocks of `Requester` struct by functionality.
pub trait GetPubKeySender {
    /// Sends the GetPubKey request and handles the GetPubKey response.
    ///
    /// GetPubKey request format:
    ///
    /// | Byte offset | Size (bytes) | Field               | Description            |
    /// | :---------- | :----------- | :------------------ | :--------------------- |
    /// | 0           | 1            | SPDMVersion         | SPDM_THIS_VERSION      |
    /// | 1           | 1            | RequestResponseCode | RequestCode::GetPubKey |
    /// | 2           | 1            | Param1              | Reserved               |
    /// | 3           | 1            | Param2              | Reserved               |
    ///
    /// GetPubKey response format:
    ///
    /// | Byte offset | Size (bytes)    | Field               | Description             |
    /// | :---------- | :-------------- | :------------------ | :---------------------- |
    /// | 0           | 1               | SPDMVersion         | SPDM_THIS_VERSION       |
    /// | 1           | 1               | RequestResponseCode | ResponseCode::GetPubKey |
    /// | 2           | 1               | Param1              | Reserved                |
    /// | 3           | 1               | Param2              | Reserved                |
    /// | 4           | PUBLIC_KEY_SIZE | PublicKey           | Public Key              |
    fn get_pub_key(&mut self) -> RequesterStatus;
}

impl<D: RequesterDeps> GetPubKeySender for Requester<D> {
    fn get_pub_key(&mut self) -> RequesterStatus {
        let mut buf = uninit_array![u8; GET_PUBLIC_KEY_RESPONSE_SIZE];

        // [SPDMVersion, RequestCode, Reserved, Reserved]
        buf[0..4]
            .as_out()
            .copy_from_slice(&[SPDM_THIS_VERSION, RequestCode::GetPubKey.0, 0, 0]);
        let resp = &*self
            .dispatch
            .dispatch_request(false, buf.as_mut().into(), 4);
        if resp.len() != GET_PUBLIC_KEY_RESPONSE_SIZE {
            return Err(RequesterError);
        }
        let resp: &GetPubKeyResponse = resp.try_into().map_err(|_| RequesterError)?;
        if !D::Identity::is_public_key_valid(&resp.public_key) {
            return Err(RequesterError);
        }
        self.session.set_responder_public_key(&resp.public_key);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "mock")]
    mod mock {
        use mocktopus::mocking::{MockResult, Mockable};
        use spdm_test_deps::{TestDispatch, TestIdentity, TEST_IDENTITY_PUBLIC_KEY};
        use zerocopy::AsBytes;

        use super::super::*;
        use crate::test::TestRequesterDeps;

        #[test]
        fn get_pub_key_success() {
            let mut requester = Requester::<TestRequesterDeps>::new(TestIdentity, TestDispatch);

            TestDispatch::dispatch_request.mock_safe(|_, _, buf, _| {
                let mut pub_key_response = vec![SPDM_THIS_VERSION, RequestCode::GetPubKey.0, 0, 0];
                pub_key_response.extend_from_slice(TEST_IDENTITY_PUBLIC_KEY.as_bytes());
                MockResult::Return(buf.copy_from_slice(&pub_key_response))
            });

            let result = requester.get_pub_key();
            assert_eq!(result, Ok(()));

            assert_eq!(
                requester.session.responder_public_key,
                Some(TEST_IDENTITY_PUBLIC_KEY)
            );
        }

        #[test]
        fn get_pub_key_invalid() {
            let mut requester = Requester::<TestRequesterDeps>::new(TestIdentity, TestDispatch);

            TestDispatch::dispatch_request.mock_safe(|_, _, buf, _| {
                let mut pub_key_response = vec![SPDM_THIS_VERSION, RequestCode::GetPubKey.0, 0, 0];
                pub_key_response.extend_from_slice(TEST_IDENTITY_PUBLIC_KEY.as_bytes());
                MockResult::Return(buf.copy_from_slice(&pub_key_response))
            });
            TestIdentity::is_public_key_valid.mock_safe(|_| MockResult::Return(false));

            let result = requester.get_pub_key();
            assert_eq!(result, Err(RequesterError));
        }

        #[test]
        fn get_pub_key_invalid_size() {
            let mut requester = Requester::<TestRequesterDeps>::new(TestIdentity, TestDispatch);

            TestDispatch::dispatch_request.mock_safe(|_, _, _, _| MockResult::Return(&mut []));

            let result = requester.get_pub_key();
            assert_eq!(result, Err(RequesterError));
        }
    }
}
