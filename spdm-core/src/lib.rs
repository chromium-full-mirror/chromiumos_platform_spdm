// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements the SPDM responder logic.

#![cfg_attr(not(test), no_std)]
mod deps;
mod dispatch;
mod session;
mod types;

use dispatch::internal::SpdmState;
pub use dispatch::SpdmDispatcher;
use session::Session;
use spdm_types::deps::SpdmDeps;

pub struct Spdm<D: SpdmDeps> {
    state: SpdmState,
    identity: D::Identity,
    vendor: D::Vendor,
    session: Session<D::Crypto>,
}

impl<D: SpdmDeps> Spdm<D> {
    pub fn new(identity: D::Identity, vendor: D::Vendor) -> Self {
        Self {
            state: SpdmState::default(),
            identity,
            vendor,
            session: Session::<D::Crypto>::default(),
        }
    }
}
