// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use uninit::prelude::*;

use super::Crypto;
use crate::deps::{CryptoResult, CryptoStatus};
use crate::types::crypto::{
    EcdsaP256Signature, Sha256Hash, ECDSA_P256_SCALAR_SIZE, SHA256_HASH_SIZE,
};

const TEST_HASH: [u8; SHA256_HASH_SIZE] = [0xFF; SHA256_HASH_SIZE];
const TEST_SIGNATURE: EcdsaP256Signature = EcdsaP256Signature {
    r: [0x0A; ECDSA_P256_SCALAR_SIZE],
    s: [0x0B; ECDSA_P256_SCALAR_SIZE],
};

pub struct TestCrypto;

impl Crypto for TestCrypto {
    type IdentityPrivateKeyHandle = ();
    type Sha256HashContext = ();

    fn sha256_init(
        ctx: Out<Self::Sha256HashContext>,
    ) -> CryptoResult<&mut Self::Sha256HashContext> {
        Ok(ctx.write(()))
    }

    fn sha256_update(_ctx: &mut Self::Sha256HashContext, _data: &[u8]) -> CryptoStatus {
        Ok(())
    }

    fn sha256_get<'a>(
        _ctx: &Self::Sha256HashContext,
        buf: Out<'a, Sha256Hash>,
    ) -> CryptoResult<&'a mut Sha256Hash> {
        Ok(buf.write(TEST_HASH))
    }

    fn sha256_final(
        _ctx: Self::Sha256HashContext,
        buf: Out<Sha256Hash>,
    ) -> CryptoResult<&mut Sha256Hash> {
        Ok(buf.write(TEST_HASH))
    }

    fn ecdsa_sign<'a>(
        _key_handle: &Self::IdentityPrivateKeyHandle,
        _hash_to_sign: &Sha256Hash,
        buf: Out<'a, EcdsaP256Signature>,
    ) -> CryptoResult<&'a mut EcdsaP256Signature> {
        Ok(buf.write(TEST_SIGNATURE))
    }
}
