// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use spdm::types::code::RequestCode;
use spdm::types::message::VERSION_RESPONSE_SIZE;
use spdm_types::deps::Dispatch;
use uninit::extension_traits::AsOut;
use uninit::uninit_array;

use crate::error::{RequesterError, RequesterStatus};
use crate::version::{SPDM_THIS_ALPHA_VERSION, SPDM_THIS_VERSION};
use crate::{Requester, RequesterDeps};

/// GetVersionSender sends the GetVersion request.
///
/// This trait is only used for separating impl blocks of `Requester` struct by functionality.
pub trait GetVersionSender {
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
    fn get_version(&mut self) -> RequesterStatus;
}

impl<D: RequesterDeps> GetVersionSender for Requester<D> {
    fn get_version(&mut self) -> RequesterStatus {
        let mut buf = uninit_array![u8; VERSION_RESPONSE_SIZE];

        // [SPDMVersion, RequestCode, Reserved, Reserved]
        const GET_VERSION_REQUEST: [u8; 4] = [0x10, RequestCode::GetVersion.0, 0, 0];
        buf[0..4].as_out().copy_from_slice(&GET_VERSION_REQUEST);
        let resp = self.dispatch.dispatch_request(false, buf.as_out(), 4);
        if resp.len() != VERSION_RESPONSE_SIZE {
            return Err(RequesterError);
        }

        if resp[6] != SPDM_THIS_VERSION || resp[7] != SPDM_THIS_ALPHA_VERSION {
            return Err(RequesterError);
        }
        self.session
            .set_negotiation_transcript(GET_VERSION_REQUEST, resp.try_into().unwrap());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "mock")]
    mod mock {
        use mocktopus::mocking::{MockResult, Mockable};
        use spdm::types::code::ResponseCode;
        use spdm_test_deps::{TestDispatch, TestIdentity};
        use spdm_types::deps::Dispatch;

        use super::super::*;
        use crate::error::RequesterError;
        use crate::test::TestRequesterDeps;

        #[test]
        fn get_version_success() {
            let mut requester = Requester::<TestRequesterDeps>::new(TestIdentity, TestDispatch);

            TestDispatch::dispatch_request.mock_safe(|_, _, buf, _| {
                MockResult::Return(buf.copy_from_slice(&[
                    0x10,
                    ResponseCode::Version.0,
                    0,
                    0,
                    0,
                    1,
                    SPDM_THIS_VERSION,
                    SPDM_THIS_ALPHA_VERSION,
                ]))
            });

            let result = requester.get_version();
            assert_eq!(result, Ok(()));

            assert_eq!(
                requester.session.transcript,
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
        }

        #[test]
        fn get_version_mismatch() {
            let mut requester = Requester::<TestRequesterDeps>::new(TestIdentity, TestDispatch);

            TestDispatch::dispatch_request.mock_safe(|_, _, buf, _| {
                MockResult::Return(buf.copy_from_slice(&[
                    0x10,
                    ResponseCode::Version.0,
                    0,
                    0,
                    0,
                    1,
                    SPDM_THIS_VERSION,
                    SPDM_THIS_ALPHA_VERSION + 1,
                ]))
            });

            let result = requester.get_version();
            assert_eq!(result, Err(RequesterError));
        }
    }
}
