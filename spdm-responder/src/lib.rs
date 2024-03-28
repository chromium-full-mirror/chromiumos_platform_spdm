// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements the SPDM responder logic.

#![cfg_attr(not(test), no_std)]
mod code;
mod dispatch;
mod error;
mod session;
mod version;

#[cfg(test)]
mod test;

use dispatch::internal::ResponderState;
pub use dispatch::Dispatcher;
use spdm::session::Session;
use spdm_types::deps::{Crypto, Identity, Vendor};

/// `ResponderDeps` defines the trait dependencies of `Responder` so it
/// only needs to be generic on a single type with `ResponderDeps` trait bound.
pub trait ResponderDeps {
    type Crypto: Crypto;
    type Identity: Identity<Crypto = Self::Crypto>;
    type Vendor: Vendor;
}

pub struct Responder<D: ResponderDeps> {
    state: ResponderState,
    identity: D::Identity,
    vendor: D::Vendor,
    session: Session<D::Crypto>,
}

impl<D: ResponderDeps> Responder<D> {
    pub fn new(identity: D::Identity, vendor: D::Vendor) -> Self {
        let session =
            Session::<D::Crypto>::with_responder_public_key(identity.identity_public_key());
        Self {
            state: ResponderState::default(),
            identity,
            vendor,
            session,
        }
    }
}
