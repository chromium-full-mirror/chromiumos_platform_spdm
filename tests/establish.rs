// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod deps;

use std::cell::RefCell;
use std::rc::Rc;

use deps::crypto::CryptoImpl;
use deps::identity::IdentityImpl;
use spdm_requester::error::RequesterError;
use spdm_requester::{Requester, RequesterDeps};
use spdm_responder::{Dispatcher, Responder, ResponderDeps};
use spdm_types::deps::{Dispatch, Vendor};
use uninit::extension_traits::AsOut;

// The simplest dispatch logic will be to own the responder itself,
// and just call `dispatch_request` on it.
pub struct DispatchToResponder<D: ResponderDeps>(Rc<RefCell<Responder<D>>>);

impl<D: ResponderDeps> Dispatch for DispatchToResponder<D> {
    fn dispatch_request<'a>(
        &mut self,
        is_secure: bool,
        mut buf: uninit::prelude::Out<'a, [u8]>,
        req_size: usize,
    ) -> &'a mut [u8] {
        // SAFETY: `dispatch_request` should only read the first `req_size` of buf, which
        // is guaranteed to be initialized. Also, the first `resp_size` of the buffer is
        // guaranteed to be initialized.
        unsafe {
            let resp_size =
                self.0
                    .borrow_mut()
                    .dispatch_request(is_secure, buf.r().assume_init(), req_size);
            buf.get_unchecked_out(..resp_size).assume_init()
        }
    }
}

pub struct RequesterDepsImpl<D: ResponderDeps> {
    _phantom: D,
}

impl<D: ResponderDeps> RequesterDeps for RequesterDepsImpl<D> {
    type Crypto = CryptoImpl;
    type Identity = IdentityImpl;
    type Dispatch = DispatchToResponder<D>;
}

// Let's make the responder respond to the vendor message by duplicating
// and reversing the second half of the request message. This is simple
// while capable of testing that we receive the request correctly, and
// that the response might be larger than the request.
pub struct Palindromize;

impl Vendor for Palindromize {
    fn process_vendor_request(&self, buf: &mut [u8], req_size: usize) -> usize {
        if buf.len() < req_size * 2 {
            return 0;
        }
        let reversed = buf[..req_size].iter().rev().cloned().collect::<Vec<u8>>();
        buf[req_size..req_size * 2].copy_from_slice(&reversed);
        req_size * 2
    }
}

pub struct ResponderDepsImpl;

impl ResponderDeps for ResponderDepsImpl {
    type Crypto = CryptoImpl;
    type Identity = IdentityImpl;
    type Vendor = Palindromize;
}

#[test]
fn test_establish() {
    let identity = IdentityImpl::try_new().expect("Failed to create Identity.");
    let responder = Responder::<ResponderDepsImpl>::new(identity, Palindromize);

    let identity = IdentityImpl::try_new().expect("Failed to create Identity.");
    let mut requester: Requester<RequesterDepsImpl<ResponderDepsImpl>> =
        Requester::<RequesterDepsImpl<_>>::new(
            identity,
            DispatchToResponder(Rc::new(RefCell::new(responder))),
        );

    requester
        .establish_session()
        .expect("Failed to establish session.");

    // Send the first vendor command.
    let mut buf = [1, 2, 3, 4, 0, 0, 0, 0];
    let buf = requester
        .dispatch_vendor_command(buf.as_out(), 4)
        .expect("Failed to dispatch vendor command.");
    assert_eq!(buf, [1, 2, 3, 4, 4, 3, 2, 1]);

    // Send the second vendor command.
    let mut buf = [3, 4, 0, 0];
    let buf = requester
        .dispatch_vendor_command(buf.as_out(), 2)
        .expect("Failed to dispatch vendor command.");
    assert_eq!(buf, [3, 4, 4, 3]);
}

#[test]
fn test_establish_failures() {
    let identity = IdentityImpl::try_new().expect("Failed to create Identity.");
    let responder = Rc::new(RefCell::new(Responder::<ResponderDepsImpl>::new(
        identity,
        Palindromize,
    )));

    let identity = IdentityImpl::try_new().expect("Failed to create Identity.");
    let mut requester: Requester<RequesterDepsImpl<ResponderDepsImpl>> =
        Requester::<RequesterDepsImpl<_>>::new(identity, DispatchToResponder(responder.clone()));

    // Dispatching vendor commands before session established should fail.
    let mut buf = [1, 2, 3, 4, 0, 0, 0, 0];
    assert_eq!(
        requester.dispatch_vendor_command(buf.as_out(), 4),
        Err(RequesterError)
    );

    requester
        .establish_session()
        .expect("Failed to establish session.");
    // Now the command should succeed.
    let buf = requester
        .dispatch_vendor_command(buf.as_out(), 4)
        .expect("Failed to dispatch vendor command.");
    assert_eq!(buf, [1, 2, 3, 4, 4, 3, 2, 1]);

    // Establishing session again should succeed.
    requester
        .establish_session()
        .expect("Failed to establish session.");
    let mut buf = [3, 4, 0, 0];
    let buf = requester
        .dispatch_vendor_command(buf.as_out(), 2)
        .expect("Failed to dispatch vendor command.");
    assert_eq!(buf, [3, 4, 4, 3]);

    // Breaking some state should cause dispatch command to fail. Let's assume another
    // requester sets up a session with the responder.
    let identity = IdentityImpl::try_new().expect("Failed to create Identity.");
    let mut requester2: Requester<RequesterDepsImpl<ResponderDepsImpl>> =
        Requester::<RequesterDepsImpl<_>>::new(identity, DispatchToResponder(responder));
    requester2
        .establish_session()
        .expect("Failed to establish session.");
    // Now the original requester should fail to send vendor command.
    let mut buf = [1, 2, 3, 0, 0, 0];
    assert_eq!(
        requester.dispatch_vendor_command(buf.as_out(), 3),
        Err(RequesterError)
    );
    // But after re-establishing the session, vendor command should work again.
    requester
        .establish_session()
        .expect("Failed to establish session.");
    let buf = requester
        .dispatch_vendor_command(buf.as_out(), 3)
        .expect("Failed to dispatch vendor command.");
    assert_eq!(buf, [1, 2, 3, 3, 2, 1]);
}
