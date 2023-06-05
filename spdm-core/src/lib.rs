// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements the SPDM responder logic.

#![cfg_attr(not(any(feature = "std", test)), no_std)]
mod code;
mod context;
mod error;
mod state;

pub use context::SpdmContext;
pub use error::UNSPECIFIED_ERROR_RESPONSE;
pub use state::SpdmState;
