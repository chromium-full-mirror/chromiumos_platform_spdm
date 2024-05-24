// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::iter::repeat;

#[cfg(feature = "mock")]
use mocktopus::macros::*;
use spdm_types::crypto::{
    AesGcm128Iv, AesGcm128Tag, EcP256UncompressedPoint, EcdsaP256Signature, Sha256Hash,
    AES_GCM_128_IV_SIZE, AES_GCM_128_TAG_SIZE, ECDSA_P256_SCALAR_SIZE, EC_P256_COORD_SIZE,
    SHA256_HASH_SIZE,
};
use spdm_types::deps::{Crypto, CryptoResult, CryptoStatus, IdentityPublicKey};
use uninit::prelude::*;

use crate::TEST_IDENTITY_PUBLIC_KEY;

const TEST_HASH: [u8; SHA256_HASH_SIZE] = [0xFF; SHA256_HASH_SIZE];
const TEST_SIGNATURE: EcdsaP256Signature = EcdsaP256Signature {
    r: [0x0A; ECDSA_P256_SCALAR_SIZE],
    s: [0x0B; ECDSA_P256_SCALAR_SIZE],
};
const TEST_PUBLIC_KEY: EcP256UncompressedPoint = EcP256UncompressedPoint {
    x: [0x0C; EC_P256_COORD_SIZE],
    y: [0x0D; EC_P256_COORD_SIZE],
};
const TEST_IV: AesGcm128Iv = [0xAB; AES_GCM_128_IV_SIZE];
const TEST_TAG: AesGcm128Tag = [0xCD; AES_GCM_128_TAG_SIZE];

pub struct TestCrypto;

pub struct IdentityPrivateKeyHandle;
pub struct Sha256HashContext;
pub struct HmacDerivationKeyHandle;
pub struct HmacSecretKeyHandle;
pub struct AesGcmKeyHandle;

#[cfg_attr(feature = "mock", mockable)]
unsafe impl Crypto for TestCrypto {
    type IdentityPrivateKeyHandle = IdentityPrivateKeyHandle;
    type Sha256HashContext = Sha256HashContext;
    type HmacDerivationKeyHandle = HmacDerivationKeyHandle;
    type HmacSecretKeyHandle = HmacSecretKeyHandle;
    type AesGcmKeyHandle = AesGcmKeyHandle;

    fn sha256_init(
        ctx: Out<Self::Sha256HashContext>,
    ) -> CryptoResult<&mut Self::Sha256HashContext> {
        Ok(ctx.write(Sha256HashContext))
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

    fn ecdsa_verify(
        _public_key: &IdentityPublicKey,
        _hash_to_sign: &Sha256Hash,
        _signature: &EcdsaP256Signature,
    ) -> CryptoStatus {
        Ok(())
    }

    fn hmac_extract_from_ecdh_with_priv<'a>(
        _their_public_key: &EcP256UncompressedPoint,
        _my_private_key: &Self::IdentityPrivateKeyHandle,
        _salt: &[u8],
        hmac_derivation_key_handle: Out<'a, Self::HmacDerivationKeyHandle>,
    ) -> CryptoResult<&'a mut Self::HmacDerivationKeyHandle> {
        Ok(hmac_derivation_key_handle.write(HmacDerivationKeyHandle))
    }

    fn hmac_extract_from_ecdh<'a, 'b>(
        _their_public_key: &EcP256UncompressedPoint,
        _salt: &[u8],
        my_public_key: Out<'a, EcP256UncompressedPoint>,
        hmac_derivation_key_handle: Out<'b, Self::HmacDerivationKeyHandle>,
    ) -> CryptoResult<(
        &'a mut EcP256UncompressedPoint,
        &'b mut Self::HmacDerivationKeyHandle,
    )> {
        Ok((
            my_public_key.write(TEST_PUBLIC_KEY),
            hmac_derivation_key_handle.write(HmacDerivationKeyHandle),
        ))
    }

    fn hmac_extract<'a>(
        _hmac_derivation_key_handle_in: &Self::HmacDerivationKeyHandle,
        _data: &[u8],
        hmac_derivation_key_handle_out: Out<'a, Self::HmacDerivationKeyHandle>,
    ) -> CryptoResult<&'a mut Self::HmacDerivationKeyHandle> {
        Ok(hmac_derivation_key_handle_out.write(HmacDerivationKeyHandle))
    }

    fn hmac_expand_hmac_secret_key<'a>(
        _hmac_derivation_key_handle: &Self::HmacDerivationKeyHandle,
        _info: &[u8],
        hmac_secret_key_handle: Out<'a, Self::HmacSecretKeyHandle>,
    ) -> CryptoResult<&'a mut Self::HmacSecretKeyHandle> {
        Ok(hmac_secret_key_handle.write(HmacSecretKeyHandle))
    }

    fn hmac_expand_derivation_key<'a>(
        _hmac_derivation_key_handle_in: &Self::HmacDerivationKeyHandle,
        _info: &[u8],
        hmac_derivation_key_handle_out: Out<'a, Self::HmacDerivationKeyHandle>,
    ) -> CryptoResult<&'a mut Self::HmacDerivationKeyHandle> {
        Ok(hmac_derivation_key_handle_out.write(HmacDerivationKeyHandle))
    }

    fn hmac_expand_aes_gcm_key<'a>(
        _hmac_derivation_key_handle: &Self::HmacDerivationKeyHandle,
        _info: &[u8],
        aes_gcm_key: Out<'a, Self::AesGcmKeyHandle>,
    ) -> CryptoResult<&'a mut Self::AesGcmKeyHandle> {
        Ok(aes_gcm_key.write(AesGcmKeyHandle))
    }

    fn hmac_expand_aes_gcm_iv<'a>(
        _hmac_derivation_key_handle: &Self::HmacDerivationKeyHandle,
        _info: &[u8],
        aes_gcm_iv: Out<'a, AesGcm128Iv>,
    ) -> CryptoResult<&'a mut AesGcm128Iv> {
        Ok(aes_gcm_iv.write(TEST_IV))
    }

    fn hmac<'a>(
        _hmac_secret_key_handle: &Self::HmacSecretKeyHandle,
        _data: &[u8],
        buf: Out<'a, Sha256Hash>,
    ) -> CryptoResult<&'a mut Sha256Hash> {
        Ok(buf.write(TEST_HASH))
    }

    fn validate_hmac(
        _hmac_secret_key_handle: &Self::HmacSecretKeyHandle,
        _data: &[u8],
        _hmac: &Sha256Hash,
    ) -> CryptoStatus {
        Ok(())
    }

    fn aes_gcm_encrypt<'a>(
        _aes_gcm_key_handle: &Self::AesGcmKeyHandle,
        _iv: &AesGcm128Iv,
        _aad: &[u8],
        _buf: &mut [u8],
        tag: Out<'a, AesGcm128Tag>,
    ) -> CryptoResult<&'a mut AesGcm128Tag> {
        Ok(tag.write(TEST_TAG))
    }

    fn aes_gcm_decrypt(
        _aes_gcm_key_handle: &Self::AesGcmKeyHandle,
        _iv: &AesGcm128Iv,
        _aad: &[u8],
        _tag: &AesGcm128Tag,
        _buf: &mut [u8],
    ) -> CryptoStatus {
        Ok(())
    }

    fn random_bytes(buf: Out<[u8]>) -> CryptoResult<&mut [u8]> {
        Ok(buf.fill_with_iter(repeat(0xDD)))
    }

    fn random_key_pair<'a, 'b>(
        private: Out<'a, Self::IdentityPrivateKeyHandle>,
        public: Out<'b, IdentityPublicKey>,
    ) -> CryptoResult<(
        &'a mut Self::IdentityPrivateKeyHandle,
        &'b mut IdentityPublicKey,
    )> {
        Ok((
            private.write(IdentityPrivateKeyHandle),
            public.write(TEST_IDENTITY_PUBLIC_KEY),
        ))
    }
}
