// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::marker::PhantomData;

use openssl::sha::Sha256;
use spdm_types::crypto::{
    AesGcm128Iv, AesGcm128Tag, EcP256UncompressedPoint, EcdsaP256Signature, Sha256Hash,
};
use spdm_types::deps::{Crypto, CryptoResult, CryptoStatus, IdentityPublicKey};
use uninit::out_ref::Out;

pub struct RawKey<T> {
    pub vec: Vec<u8>,
    phantom: PhantomData<T>,
}

pub struct IdentityPrivateKeyTag;
pub struct HmacDerivationKeyTag;
pub struct HmacSecretKeyTag;
pub struct AesGcmKeyTag;

pub struct CryptoImpl;

// TODO(b/338528575): Implement Crypto for CryptoImpl.
#[allow(unused_variables)]
impl Crypto for CryptoImpl {
    type IdentityPrivateKeyHandle = RawKey<IdentityPrivateKeyTag>;
    type Sha256HashContext = Sha256;
    type HmacDerivationKeyHandle = RawKey<HmacDerivationKeyTag>;
    type HmacSecretKeyHandle = RawKey<HmacSecretKeyTag>;
    type AesGcmKeyHandle = RawKey<AesGcmKeyTag>;

    fn sha256_init(
        ctx: Out<Self::Sha256HashContext>,
    ) -> CryptoResult<&mut Self::Sha256HashContext> {
        unimplemented!()
    }

    fn sha256_update(ctx: &mut Self::Sha256HashContext, data: &[u8]) -> CryptoStatus {
        unimplemented!()
    }

    fn sha256_get<'a>(
        ctx: &Self::Sha256HashContext,
        buf: Out<'a, Sha256Hash>,
    ) -> CryptoResult<&'a mut Sha256Hash> {
        unimplemented!()
    }

    fn sha256_final(
        ctx: Self::Sha256HashContext,
        buf: Out<Sha256Hash>,
    ) -> CryptoResult<&mut Sha256Hash> {
        unimplemented!()
    }

    fn ecdsa_sign<'a>(
        key_handle: &Self::IdentityPrivateKeyHandle,
        hash_to_sign: &Sha256Hash,
        buf: Out<'a, EcdsaP256Signature>,
    ) -> CryptoResult<&'a mut EcdsaP256Signature> {
        unimplemented!()
    }

    fn ecdsa_verify(
        public_key: &IdentityPublicKey,
        hash_to_sign: &Sha256Hash,
        signature: &EcdsaP256Signature,
    ) -> CryptoStatus {
        unimplemented!()
    }

    fn hmac_extract_from_ecdh_with_priv<'a>(
        their_public_key: &EcP256UncompressedPoint,
        my_private_key: &Self::IdentityPrivateKeyHandle,
        salt: &[u8],
        hmac_derivation_key_handle: Out<'a, Self::HmacDerivationKeyHandle>,
    ) -> CryptoResult<&'a mut Self::HmacDerivationKeyHandle> {
        unimplemented!()
    }

    fn hmac_extract_from_ecdh<'a, 'b>(
        their_public_key: &EcP256UncompressedPoint,
        salt: &[u8],
        my_public_key: Out<'a, EcP256UncompressedPoint>,
        hmac_derivation_key_handle: Out<'b, Self::HmacDerivationKeyHandle>,
    ) -> CryptoResult<(
        &'a mut EcP256UncompressedPoint,
        &'b mut Self::HmacDerivationKeyHandle,
    )> {
        unimplemented!()
    }

    fn hmac_extract<'a>(
        hmac_derivation_key_handle_in: &Self::HmacDerivationKeyHandle,
        data: &[u8],
        hmac_derivation_key_handle_out: Out<'a, Self::HmacDerivationKeyHandle>,
    ) -> CryptoResult<&'a mut Self::HmacDerivationKeyHandle> {
        unimplemented!()
    }

    fn hmac_expand_hmac_secret_key<'a>(
        hmac_derivation_key_handle: &Self::HmacDerivationKeyHandle,
        info: &[u8],
        hmac_secret_key_handle: Out<'a, Self::HmacSecretKeyHandle>,
    ) -> CryptoResult<&'a mut Self::HmacSecretKeyHandle> {
        unimplemented!()
    }

    fn hmac_expand_derivation_key<'a>(
        hmac_derivation_key_handle_in: &Self::HmacDerivationKeyHandle,
        info: &[u8],
        hmac_derivation_key_handle_out: Out<'a, Self::HmacDerivationKeyHandle>,
    ) -> CryptoResult<&'a mut Self::HmacDerivationKeyHandle> {
        unimplemented!()
    }

    fn hmac_expand_aes_gcm_key<'a>(
        hmac_derivation_key_handle: &Self::HmacDerivationKeyHandle,
        info: &[u8],
        aes_gcm_key: Out<'a, Self::AesGcmKeyHandle>,
    ) -> CryptoResult<&'a mut Self::AesGcmKeyHandle> {
        unimplemented!()
    }

    fn hmac_expand_aes_gcm_iv<'a>(
        hmac_derivation_key_handle: &Self::HmacDerivationKeyHandle,
        info: &[u8],
        aes_gcm_iv: Out<'a, AesGcm128Iv>,
    ) -> CryptoResult<&'a mut AesGcm128Iv> {
        unimplemented!()
    }

    fn hmac<'a>(
        hmac_secret_key_handle: &Self::HmacSecretKeyHandle,
        data: &[u8],
        buf: Out<'a, Sha256Hash>,
    ) -> CryptoResult<&'a mut Sha256Hash> {
        unimplemented!()
    }

    fn validate_hmac(
        hmac_secret_key_handle: &Self::HmacSecretKeyHandle,
        data: &[u8],
        hmac: &Sha256Hash,
    ) -> CryptoStatus {
        unimplemented!()
    }

    fn aes_gcm_encrypt<'a>(
        aes_gcm_key_handle: &Self::AesGcmKeyHandle,
        iv: &AesGcm128Iv,
        aad: &[u8],
        buf: &mut [u8],
        tag: Out<'a, AesGcm128Tag>,
    ) -> CryptoResult<&'a mut AesGcm128Tag> {
        unimplemented!()
    }

    fn aes_gcm_decrypt(
        aes_gcm_key_handle: &Self::AesGcmKeyHandle,
        iv: &AesGcm128Iv,
        aad: &[u8],
        tag: &AesGcm128Tag,
        buf: &mut [u8],
    ) -> CryptoStatus {
        unimplemented!()
    }

    fn random_bytes(buf: Out<[u8]>) -> CryptoResult<&mut [u8]> {
        unimplemented!()
    }

    fn random_key_pair<'a, 'b>(
        private: Out<'a, Self::IdentityPrivateKeyHandle>,
        public: Out<'b, IdentityPublicKey>,
    ) -> CryptoResult<(
        &'a mut Self::IdentityPrivateKeyHandle,
        &'b mut IdentityPublicKey,
    )> {
        unimplemented!()
    }
}
