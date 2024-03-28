// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use open_enum::open_enum;
use spdm_proc_macros::cfg_host_attr;
use spdm_types::deps::CryptoError;

#[repr(u8)]
#[open_enum]
#[cfg_host_attr(derive(Debug))]
#[derive(Clone, Copy)]
pub enum ErrorCode {
    // One or more request fields are invalid.
    InvalidRequest = 0x01,
    // Received a (supported) request at an incorrect state.
    UnexpectedRequest = 0x04,
    // This is used as all kinds of internal errors.
    Unspecified = 0x05,
    // Cannot decrypt or verify data during the session.
    DecryptError = 0x06,
    // The RequestResponseCode in the request message is unsupported.
    UnsupportedRequest = 0x07,
    // The message received is only allowed within a session.
    SessionRequired = 0x0B,
    // The response is larger than the writable size of the buffer. Note that
    // we don't attach the ExtendedErrorData here to keep errors simple.
    ResponseTooLarge = 0x0D,
    // Requested SPDM version is not supported or is a different
    // version from the selected version.
    VersionMismatch = 0x41,
}

impl From<CryptoError> for ErrorCode {
    /// Always default to Unspecified for `Crypto` errors.
    fn from(_value: CryptoError) -> Self {
        ErrorCode::Unspecified
    }
}

// Helpful `Result` alias that use `ErrorCode` as error type.
pub type SpdmResult<T> = Result<T, ErrorCode>;
pub type SpdmStatus = SpdmResult<()>;
