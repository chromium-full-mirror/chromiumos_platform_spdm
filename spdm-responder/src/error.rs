// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use spdm::types::code::ResponseCode;
use spdm::types::error::ErrorCode;

use crate::version::SPDM_THIS_VERSION;

/// Writes the error response containing the specified `error` to `buf`.
///
/// Error response format:
///
/// | Byte offset | Size (bytes) | Field               | Description         |
/// | :---------- | :----------- | :------------------ | :------------------ |
/// | 0           | 1            | SPDMVersion         | SPDM_THIS_VERSION   |
/// | 1           | 1            | RequestResponseCode | ResponseCode::Error |
/// | 2           | 1            | Param1              | Error code          |
/// | 3           | 1            | Param2              | Error data          |
pub fn error_response(buf: &mut [u8], code: ErrorCode) -> usize {
    // No space to write even an error response. Return an empty response buffer.
    if buf.len() < 4 {
        return 0;
    }
    buf[0] = SPDM_THIS_VERSION;
    buf[1] = ResponseCode::Error.0;
    buf[2] = code.0;
    // We haven't introduced any errors that need to set the Param2 field.
    buf[3] = 0;
    4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_error_buffer_too_small() {
        let mut buf = [0; 3];
        assert_eq!(error_response(&mut buf, ErrorCode::Unspecified), 0);
    }

    #[test]
    fn write_error_success() {
        let mut buf = [0; 10];
        let error = ErrorCode::Unspecified;
        assert_eq!(error_response(&mut buf, ErrorCode::Unspecified), 4);
        let expected_data = [SPDM_THIS_VERSION, ResponseCode::Error.0, error.0, 0];
        assert_eq!(buf[0..4], expected_data[..]);
    }
}
