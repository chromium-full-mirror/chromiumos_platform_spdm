// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::code::{ResponseCode, SPDM_THIS_VERSION};

/// The unspecified error response that should be returned when internal errors
/// occurred. This constant can be useful for the library's user when it can't
/// even dispatch a request to the SPDM state machine (e.g., if context/state
/// initialization failed).
pub const UNSPECIFIED_ERROR_RESPONSE: [u8; 4] = [
    SPDM_THIS_VERSION,
    ResponseCode::Error as u8,
    ErrorCode::Unspecified as u8,
    0,
];

#[repr(u8)]
pub enum ErrorCode {
    // This is used as all kinds of internal errors.
    Unspecified = 0x05,
}

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
pub fn write_error(buf: &mut [u8], error: ErrorCode) -> usize {
    // No space to write even an error response. Return an empty response buffer.
    if buf.len() < 4 {
        return 0;
    }
    buf[0] = SPDM_THIS_VERSION;
    buf[1] = ResponseCode::Error as u8;
    buf[2] = error as u8;
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
        assert_eq!(write_error(&mut buf, ErrorCode::Unspecified), 0);
    }

    #[test]
    fn write_error_success() {
        let mut buf = [0; 10];
        let error = ErrorCode::Unspecified;
        assert_eq!(write_error(&mut buf, ErrorCode::Unspecified), 4);
        let expected_data = [SPDM_THIS_VERSION, ResponseCode::Error as u8, error as u8, 0];
        assert_eq!(buf[0..4], expected_data[..]);
    }
}
