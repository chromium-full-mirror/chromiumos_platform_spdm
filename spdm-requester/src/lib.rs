// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements the SPDM requester logic.

#[cfg(test)]
mod test;

mod dispatch;
pub mod error;
mod establish;
mod session;
mod version;

use dispatch::DispatchSecure;
use error::{RequesterResult, RequesterStatus};
use establish::finish::FinishSender;
use establish::get_public_key::GetPubKeySender;
use establish::get_version::GetVersionSender;
use establish::give_public_key::GivePubKeySender;
use establish::key_exchange::KeyExchangeSender;
use spdm::session::{Session, SpdmRole};
use spdm_types::deps::{Crypto, Dispatch, Identity};
use uninit::out_ref::Out;

/// `RequesterDeps` defines the trait dependencies of `Requester` so it
/// only needs to be generic on a single type with `RequesterDeps` trait bound.
pub trait RequesterDeps {
    type Crypto: Crypto;
    type Identity: Identity<Crypto = Self::Crypto>;
    type Dispatch: Dispatch;
}

pub struct Requester<D: RequesterDeps> {
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

    // Establishes the SPDM session. Returns Ok on success.
    pub fn establish_session(&mut self) -> RequesterStatus {
        self.session.reset_session(SpdmRole::Requester);
        self.get_version()?;
        self.get_pub_key()?;
        self.key_exchange()?;
        self.give_pub_key()?;
        self.finish()?;
        Ok(())
    }

    pub fn dispatch_vendor_command<'a>(
        &mut self,
        buf: Out<'a, [u8]>,
        req_size: usize,
    ) -> RequesterResult<&'a mut [u8]> {
        self.dispatch_vendor_request(buf, req_size)
    }
}
