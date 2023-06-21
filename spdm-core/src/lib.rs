// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements the SPDM responder logic.

#![cfg_attr(not(any(feature = "std", test)), no_std)]
pub mod deps;
mod dispatch;
pub(crate) mod types;

use deps::SpdmDeps;
pub use dispatch::SpdmDispatcher;
pub use types::error::UNSPECIFIED_ERROR_RESPONSE;

pub struct Spdm<D: SpdmDeps> {
    // LINT: This will be used soon, if we don't put this here now we have to add
    // a phantom data field.
    #[allow(dead_code)]
    identity: D::Identity,
}

impl<D: SpdmDeps> Spdm<D> {
    pub fn new(identity: D::Identity) -> Self {
        Self { identity }
    }
}
