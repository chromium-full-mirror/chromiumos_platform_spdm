// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use spdm::deps::{Crypto, CryptoResult, CryptoStatus, Identity, IdentityPublicKey, SpdmDeps};
use spdm::types::crypto::{EcdsaP256Signature, Sha256Hash};
use uninit::prelude::*;

type IdentityPrivateKey = [u8; 32];

/// Implements Crypto by interacting with the static eal functions.
pub struct EalCrypto;

impl Crypto for EalCrypto {
    /// Use raw private key for eal's private key handle.
    type IdentityPrivateKeyHandle = IdentityPrivateKey;
    // TODO(b/284404632): Decide some crypto types for eal.
    type Sha256HashContext = ();

    fn sha256_init(
        _ctx: Out<Self::Sha256HashContext>,
    ) -> CryptoResult<&mut Self::Sha256HashContext> {
        unimplemented!()
    }

    fn sha256_update(_ctx: &mut Self::Sha256HashContext, _data: &[u8]) -> CryptoStatus {
        unimplemented!()
    }

    fn sha256_get<'a>(
        _ctx: &Self::Sha256HashContext,
        _buf: Out<'a, Sha256Hash>,
    ) -> CryptoResult<&'a mut Sha256Hash> {
        unimplemented!()
    }

    fn sha256_final(
        _ctx: Self::Sha256HashContext,
        _buf: Out<Sha256Hash>,
    ) -> CryptoResult<&mut Sha256Hash> {
        unimplemented!()
    }

    fn ecdsa_sign<'a>(
        _key_handle: &Self::IdentityPrivateKeyHandle,
        _hash_to_sign: &Sha256Hash,
        _buf: Out<'a, EcdsaP256Signature>,
    ) -> CryptoResult<&'a mut EcdsaP256Signature> {
        unimplemented!()
    }
}

/// Implements Identity by interacting with the static eal functions.
pub struct EalIdentity;

impl Identity for EalIdentity {
    type Crypto = EalCrypto;

    fn identity_public_key(&self) -> &IdentityPublicKey {
        unimplemented!()
    }

    fn identity_private_key_handle(&self) -> &IdentityPrivateKey {
        unimplemented!()
    }
}

pub struct SpdmEalDeps;

impl SpdmDeps for SpdmEalDeps {
    type Crypto = EalCrypto;
    type Identity = EalIdentity;
}
