// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use spdm_responder::ResponderDeps;
use spdm_types::crypto::{
    AesGcm128Iv, AesGcm128Tag, EcP256UncompressedPoint, EcdsaP256Signature, Sha256Hash,
};
use spdm_types::deps::{Crypto, CryptoResult, CryptoStatus, Identity, IdentityPublicKey, Vendor};
use uninit::prelude::*;

type IdentityPrivateKey = [u8; 32];

/// Implements Crypto by interacting with the static eal functions.
pub struct EalCrypto;

pub struct Sha256HashContext;
pub struct HmacDerivationKeyHandle;
pub struct HmacSecretKeyHandle;
pub struct AesGcmKeyHandle;

unsafe impl Crypto for EalCrypto {
    /// Use raw private key for eal's private key handle.
    type IdentityPrivateKeyHandle = IdentityPrivateKey;
    // TODO(b/284404632): Decide some crypto types for eal.
    type Sha256HashContext = Sha256HashContext;
    type HmacDerivationKeyHandle = HmacDerivationKeyHandle;
    type HmacSecretKeyHandle = HmacSecretKeyHandle;
    type AesGcmKeyHandle = AesGcmKeyHandle;

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

    fn ecdsa_verify(
        _public_key: &IdentityPublicKey,
        _hash_to_sign: &Sha256Hash,
        _signature: &EcdsaP256Signature,
    ) -> CryptoStatus {
        unimplemented!()
    }

    fn hmac_extract_from_ecdh<'a, 'b>(
        _their_public_key: &EcP256UncompressedPoint,
        _salt: &[u8],
        _my_public_key: Out<'a, EcP256UncompressedPoint>,
        _hmac_derivation_key_handle: Out<'b, Self::HmacDerivationKeyHandle>,
    ) -> CryptoResult<(
        &'a mut EcP256UncompressedPoint,
        &'b mut Self::HmacDerivationKeyHandle,
    )> {
        unimplemented!()
    }

    fn hmac_extract_from_ecdh_with_priv<'a>(
        _their_public_key: &EcP256UncompressedPoint,
        _my_private_key: &Self::IdentityPrivateKeyHandle,
        _salt: &[u8],
        _hmac_derivation_key_handle: Out<'a, Self::HmacDerivationKeyHandle>,
    ) -> CryptoResult<&'a mut Self::HmacDerivationKeyHandle> {
        unimplemented!()
    }

    fn hmac_extract<'a>(
        _hmac_derivation_key_handle_in: &Self::HmacDerivationKeyHandle,
        _data: &[u8],
        _hmac_derivation_key_handle_out: Out<'a, Self::HmacDerivationKeyHandle>,
    ) -> CryptoResult<&'a mut Self::HmacDerivationKeyHandle> {
        unimplemented!()
    }

    fn hmac_expand_hmac_secret_key<'a>(
        _hmac_derivation_key_handle: &Self::HmacDerivationKeyHandle,
        _info: &[u8],
        _hmac_secret_key_handle: Out<'a, Self::HmacSecretKeyHandle>,
    ) -> CryptoResult<&'a mut Self::HmacSecretKeyHandle> {
        unimplemented!()
    }

    fn hmac_expand_derivation_key<'a>(
        _hmac_derivation_key_handle_in: &Self::HmacDerivationKeyHandle,
        _info: &[u8],
        _hmac_derivation_key_handle_out: Out<'a, Self::HmacDerivationKeyHandle>,
    ) -> CryptoResult<&'a mut Self::HmacDerivationKeyHandle> {
        unimplemented!()
    }

    fn hmac_expand_aes_gcm_key<'a>(
        _hmac_derivation_key_handle: &Self::HmacDerivationKeyHandle,
        _info: &[u8],
        _aes_gcm_key: Out<'a, Self::AesGcmKeyHandle>,
    ) -> CryptoResult<&'a mut Self::AesGcmKeyHandle> {
        unimplemented!()
    }

    fn hmac_expand_aes_gcm_iv<'a>(
        _hmac_derivation_key_handle: &Self::HmacDerivationKeyHandle,
        _info: &[u8],
        _aes_gcm_iv: Out<'a, AesGcm128Iv>,
    ) -> CryptoResult<&'a mut AesGcm128Iv> {
        unimplemented!()
    }

    fn hmac<'a>(
        _hmac_secret_key_handle: &Self::HmacSecretKeyHandle,
        _data: &[u8],
        _buf: Out<'a, Sha256Hash>,
    ) -> CryptoResult<&'a mut Sha256Hash> {
        unimplemented!()
    }

    fn validate_hmac(
        _hmac_secret_key_handle: &Self::HmacSecretKeyHandle,
        _data: &[u8],
        _hmac: &Sha256Hash,
    ) -> CryptoStatus {
        unimplemented!()
    }

    fn aes_gcm_encrypt<'a>(
        _aes_gcm_key_handle: &Self::AesGcmKeyHandle,
        _iv: &AesGcm128Iv,
        _aad: &[u8],
        _buf: &mut [u8],
        _tag: Out<'a, AesGcm128Tag>,
    ) -> CryptoResult<&'a mut AesGcm128Tag> {
        unimplemented!()
    }

    fn aes_gcm_decrypt(
        _aes_gcm_key_handle: &Self::AesGcmKeyHandle,
        _iv: &AesGcm128Iv,
        _aad: &[u8],
        _tag: &AesGcm128Tag,
        _buf: &mut [u8],
    ) -> CryptoStatus {
        unimplemented!()
    }

    fn random_bytes(_buf: Out<[u8]>) -> CryptoResult<&mut [u8]> {
        unimplemented!()
    }

    fn random_key_pair<'a, 'b>(
        _private: Out<'a, Self::IdentityPrivateKeyHandle>,
        _public: Out<'b, IdentityPublicKey>,
    ) -> CryptoResult<(
        &'a mut Self::IdentityPrivateKeyHandle,
        &'b mut IdentityPublicKey,
    )> {
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

    fn is_public_key_valid(_public_key: &EcP256UncompressedPoint) -> bool {
        unimplemented!()
    }
}

/// Implements Vendor by interacting with the eal callback functions.
pub struct EalVendor;

impl Vendor for EalVendor {
    fn process_vendor_request(&self, _buf: &mut [u8], _req_size: usize) -> usize {
        unimplemented!()
    }
}

pub struct EalResponderDeps;

impl ResponderDeps for EalResponderDeps {
    type Crypto = EalCrypto;
    type Identity = EalIdentity;
    type Vendor = EalVendor;
}
