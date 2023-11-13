// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use spdm_types::deps::{Identity, IdentityPublicKey, SpdmDeps};
use zerocopy::AsBytes;

use crate::types::code::ResponseCode;
use crate::types::error::{ErrorCode, SpdmResult};
use crate::types::message::GET_PUBLIC_KEY_RESPONSE_SIZE;
use crate::Spdm;

/// GetPubKeyDispatcher handles the GetPubKey request.
///
/// This trait is only used for separating impl blocks of `Spdm` struct by functionality.
pub trait GetPubKeyDispatcher {
    /// Handles the GetPubKey request and if successful, writes the GetPubKey response to `buf`.
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
    fn dispatch_get_pub_key_request(
        &mut self,
        buf: &mut [u8],
        req_size: usize,
    ) -> SpdmResult<usize>;
}

impl<D: SpdmDeps> GetPubKeyDispatcher for Spdm<D> {
    fn dispatch_get_pub_key_request(
        &mut self,
        buf: &mut [u8],
        // All non-reserved fields have been checked by `parse_header` so we don't need to
        // read the request again.
        _req_size: usize,
    ) -> SpdmResult<usize> {
        if buf.len() < GET_PUBLIC_KEY_RESPONSE_SIZE {
            return Err(ErrorCode::ResponseTooLarge);
        }
        buf[1] = ResponseCode::GetPubKey.0;
        buf[4..4 + IdentityPublicKey::SIZE]
            .copy_from_slice(self.identity.identity_public_key().as_bytes());
        Ok(GET_PUBLIC_KEY_RESPONSE_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::{SpdmTestDeps, TestIdentity, TestVendor, TEST_IDENTITY_PUBLIC_KEY};
    use crate::dispatch::internal::SpdmState;
    use crate::types::code::RequestCode;
    use crate::types::version::SPDM_THIS_VERSION;

    #[test]
    fn get_pub_key_request() {
        let mut buf = vec![SPDM_THIS_VERSION, RequestCode::GetPubKey.0, 0, 0];
        buf.extend_from_slice(&[0; 100]);
        let req_size = 4;

        let mut spdm = Spdm::<SpdmTestDeps>::new(TestIdentity, TestVendor);

        let result = spdm.dispatch_get_pub_key_request(&mut buf, req_size);
        assert_eq!(result, Ok(GET_PUBLIC_KEY_RESPONSE_SIZE));
        assert_eq!(
            &buf[4..GET_PUBLIC_KEY_RESPONSE_SIZE],
            TEST_IDENTITY_PUBLIC_KEY.as_bytes()
        );
        assert!(matches!(spdm.state, SpdmState::WaitForKeyExchange));
    }
}
