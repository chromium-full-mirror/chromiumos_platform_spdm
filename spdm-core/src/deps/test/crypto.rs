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
use spdm_types::deps::{Crypto, CryptoResult, CryptoStatus};
use uninit::prelude::*;

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

#[cfg_attr(feature = "mock", mockable)]
impl Crypto for TestCrypto {
    type IdentityPrivateKeyHandle = ();
    type Sha256HashContext = ();
    type HmacDerivationKeyHandle = ();
    type HmacSecretKeyHandle = ();
    type AesGcmKeyHandle = ();

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
            hmac_derivation_key_handle.write(()),
        ))
    }

    fn hmac_expand_hmac_secret_key<'a>(
        _hmac_derivation_key_handle: &Self::HmacDerivationKeyHandle,
        _info: &[u8],
        hmac_secret_key_handle: Out<'a, Self::HmacSecretKeyHandle>,
    ) -> CryptoResult<&'a mut Self::HmacSecretKeyHandle> {
        Ok(hmac_secret_key_handle.write(()))
    }

    fn hmac_expand_derivation_key<'a>(
        _hmac_derivation_key_handle_in: &Self::HmacDerivationKeyHandle,
        _info: &[u8],
        hmac_derivation_key_handle_out: Out<'a, Self::HmacDerivationKeyHandle>,
    ) -> CryptoResult<&'a mut Self::HmacDerivationKeyHandle> {
        Ok(hmac_derivation_key_handle_out.write(()))
    }

    fn hmac_expand_aes_gcm_key<'a>(
        _hmac_secret_key_handle: &Self::HmacSecretKeyHandle,
        _info: &[u8],
        aes_gcm_key: Out<'a, Self::AesGcmKeyHandle>,
    ) -> CryptoResult<&'a mut Self::AesGcmKeyHandle> {
        Ok(aes_gcm_key.write(()))
    }

    fn hmac_expand_aes_gcm_iv<'a>(
        _hmac_secret_key_handle: &Self::HmacSecretKeyHandle,
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
        Ok(buf.init_with(repeat(0xDD)))
    }
}
