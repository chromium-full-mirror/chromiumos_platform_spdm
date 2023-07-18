// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements the SPDM responder logic.

#![cfg_attr(not(any(feature = "std", test)), no_std)]
mod deps;
mod dispatch;
mod session;
mod types;

use dispatch::internal::SpdmState;
pub use dispatch::SpdmDispatcher;
use session::Session;
use spdm_types::deps::SpdmDeps;
pub use types::error::UNSPECIFIED_ERROR_RESPONSE;

pub struct Spdm<D: SpdmDeps> {
    state: SpdmState,
    identity: D::Identity,
    session: Session<D::Crypto>,
}

impl<D: SpdmDeps> Spdm<D> {
    pub fn new(identity: D::Identity) -> Self {
        Self {
            state: SpdmState::default(),
            identity,
            session: Session::<D::Crypto>::default(),
        }
    }
}
