// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use open_enum::open_enum;

use super::error::{ErrorCode, SpdmResult};
use super::version::SPDM_THIS_VERSION;

const VERSION_OFFSET: usize = 0;
const REQUEST_CODE_OFFSET: usize = 1;

#[repr(u8)]
#[open_enum]
#[derive(Copy, Clone)]
#[cfg_attr(test, derive(Debug))]
pub enum RequestCode {
    GetVersion = 0x84,
}

#[repr(u8)]
#[open_enum]
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug))]
pub enum ResponseCode {
    Version = 0x04,
    Error = 0x7F,
}

fn is_request_code_supported(code: RequestCode) -> bool {
    matches!(code, RequestCode::GetVersion)
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
}
