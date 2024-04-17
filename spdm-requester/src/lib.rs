// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements the SPDM requester logic.

#![cfg_attr(not(test), no_std)]

#[cfg(test)]
mod test;

mod error;
mod establish;
mod version;

use error::{RequesterError, RequesterStatus};
use establish::get_version::GetVersionSender;
use spdm::session::Session;
use spdm_types::deps::{Crypto, Dispatch, Identity};

/// `RequesterDeps` defines the trait dependencies of `Requester` so it
/// only needs to be generic on a single type with `RequesterDeps` trait bound.
pub trait RequesterDeps {
    type Crypto: Crypto;
    type Identity: Identity<Crypto = Self::Crypto>;
    type Dispatch: Dispatch;
}

pub struct Requester<D: RequesterDeps> {
    // Will be used soon.
    #[allow(unused)]
    identity: D::Identity,
    dispatch: D::Dispatch,
    session: Session<D::Crypto>,
}

impl<D: RequesterDeps> Requester<D> {
    pub fn new(identity: D::Identity, dispatch: D::Dispatch) -> Self {
        let session =
            Session::<D::Crypto>::with_requester_public_key(identity.identity_public_key());
        Self {
            identity,
            dispatch,
            session,
        }
    }

    pub fn establish_session(&mut self) -> RequesterStatus {
        self.session.reset_session();
        self.get_version()?;
        // TODO(b/335386464): Implement rest of the session establishment.
        Err(RequesterError)
    }
}
