// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use open_enum::open_enum;
use zerocopy::{AsBytes, FromBytes};

use super::error::{ErrorCode, SpdmResult};
use super::version::SPDM_THIS_VERSION;

const VERSION_OFFSET: usize = 0;
const REQUEST_CODE_OFFSET: usize = 1;

#[repr(u8)]
#[open_enum]
#[derive(Copy, Clone, FromBytes, AsBytes)]
#[cfg_attr(test, derive(Debug))]
pub enum RequestCode {
    GetVersion = 0x84,
    KeyExchange = 0xE4,
    Finish = 0xE5,
    // We use reserved request codes as the Get/GivePubKey request codes because
    // we don't want to parse them as vendor commands.
    GetPubKey = 0xF0,
    GivePubKey = 0xF1,
    VendorCommand = 0xF2,
}

#[repr(u8)]
#[open_enum]
#[derive(Clone, Copy, FromBytes, AsBytes)]
#[cfg_attr(test, derive(Debug))]
pub enum ResponseCode {
    Version = 0x04,
    KeyExchange = 0x64,
    Finish = 0x65,
    Error = 0x7F,
    // We use reserved response codes as the Get/GivePubKey response code because
    // we don't want to parse them as vendor commands.
    GetPubKey = 0x10,
    GivePubKey = 0x11,
    VendorCommand = 0x12,
}

// `Param1` and `Param2` are 1-byte params that appear in most SPDM message formats
// as the 3rd and 4th bytes.
pub type Param1 = u8;
pub type Param2 = u8;

fn is_request_code_supported(code: RequestCode) -> bool {
    matches!(
        code,
        RequestCode::GetVersion
            | RequestCode::KeyExchange
            | RequestCode::Finish
            | RequestCode::GetPubKey
            | RequestCode::GivePubKey
            | RequestCode::VendorCommand
    )
}

pub fn parse_header(req: &[u8]) -> SpdmResult<RequestCode> {
    if req.len() < REQUEST_CODE_OFFSET + 1 {
        return Err(ErrorCode::InvalidRequest);
    }
    let version = req[VERSION_OFFSET];
    let request_code = RequestCode(req[REQUEST_CODE_OFFSET]);
    let expected_version = if request_code == RequestCode::GetVersion {
        0x10
    } else {
        SPDM_THIS_VERSION
    };
    if version != expected_version {
        return Err(ErrorCode::VersionMismatch);
    }
    if !is_request_code_supported(request_code) {
        return Err(ErrorCode::UnsupportedRequest);
    }
    Ok(request_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_too_small() {
        let buf = [SPDM_THIS_VERSION];
        assert_eq!(parse_header(&buf), Err(ErrorCode::InvalidRequest));
    }

    #[test]
    fn version_mismatch() {
        let buf = [0x20, 0xFF];
        assert_eq!(parse_header(&buf), Err(ErrorCode::VersionMismatch));
    }

    #[test]
    fn get_version_version_mismatch() {
        // GetVersion request's version should always be 0x10.
        let buf = [SPDM_THIS_VERSION, RequestCode::GetVersion.0];
        assert_eq!(parse_header(&buf), Err(ErrorCode::VersionMismatch));
    }

    #[test]
    fn unsupported_request() {
        const GET_DIGESTS: u8 = 0x81;
        let buf = [SPDM_THIS_VERSION, GET_DIGESTS];
        assert_eq!(parse_header(&buf), Err(ErrorCode::UnsupportedRequest));
    }

    #[test]
    fn get_version() {
        // GetVersion request's version should always be 0x10.
        let buf = [0x10, RequestCode::GetVersion.0];
        assert_eq!(parse_header(&buf), Ok(RequestCode::GetVersion));
    }

    #[test]
    fn normal_request() {
        let buf = [SPDM_THIS_VERSION, RequestCode::GetPubKey.0];
        assert_eq!(parse_header(&buf), Ok(RequestCode::GetPubKey));
    }
}
