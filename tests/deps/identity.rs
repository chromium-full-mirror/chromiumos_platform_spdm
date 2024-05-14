// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::mem::MaybeUninit;

use spdm_types::crypto::EcP256UncompressedPoint;
use spdm_types::deps::{Crypto, Identity, IdentityPublicKey};
use uninit::extension_traits::AsOut;

use super::crypto::{CryptoImpl, IdentityPrivateKeyTag, RawKey};

pub struct IdentityImpl {
    private: RawKey<IdentityPrivateKeyTag>,
    public: IdentityPublicKey,
}

impl IdentityImpl {
    pub fn try_new() -> Option<Self> {
        let mut private = MaybeUninit::<RawKey<IdentityPrivateKeyTag>>::uninit();
        let mut public = MaybeUninit::<IdentityPublicKey>::uninit();
        if <Self as Identity>::Crypto::random_key_pair(private.as_out(), public.as_out()).is_ok() {
            // SAFETY: `private` and `public` are guaranteed to be initialized after
            // successful `random_key_pair`.
            unsafe {
                Some(Self {
                    private: private.assume_init(),
                    public: public.assume_init(),
                })
            }
        } else {
            None
        }
    }
}

// TODO(b/338528575): Implement Identity for IdentityImpl.
impl Identity for IdentityImpl {
    type Crypto = CryptoImpl;

    fn identity_public_key(&self) -> &IdentityPublicKey {
        &self.public
    }

    fn identity_private_key_handle(&self) -> &RawKey<IdentityPrivateKeyTag> {
        &self.private
    }

    fn is_public_key_valid(public_key: &EcP256UncompressedPoint) -> bool {
        CryptoImpl::is_public_key_valid(public_key).unwrap_or(false)
    }
}
