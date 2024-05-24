// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use uninit::prelude::*;

use super::IdentityPublicKey;
use crate::crypto::{
    AesGcm128Iv, AesGcm128Tag, EcP256UncompressedPoint, EcdsaP256Signature, Sha256Hash,
};

/// In the `Crypto` trait, we only care about success/failure instead of the actual
/// failure status because SPDM error response doesn't have space to propagate
/// different kind of crypto errors. Instead of using `bool` and `Option` as return
/// values, we still want to use status in case we forgot to handle a `false`/`None`
/// return value.
pub struct CryptoError;
pub type CryptoResult<T> = Result<T, CryptoError>;
pub type CryptoStatus = CryptoResult<()>;

/// Crypto trait defines the interface of cryptographic functions and types
/// used in SPDM. Crypto methods should be purely static.
/// # Safety
/// Many trait methods of this trait take `Out` parameters and returns a `Result`.
/// The implementation must guarantee that when those methods return `Ok`, all
/// the `Out` parameters' pointees have been initialized. This way the caller can
/// safely assume that after the method call returns `Ok` the `MaybeUninit` parameters
/// they passed are guaranteed to be initialized.
pub unsafe trait Crypto {
    type IdentityPrivateKeyHandle;
    /// This is the context object for SHA256 hash operations.
    type Sha256HashContext;
    /// This is the key produced by HMAC-extract which needs to go through HMAC-expand
    /// before being used.
    type HmacDerivationKeyHandle;
    /// This is the key handle for secrets that can be used to perform ordinary
    /// HMACs.
    type HmacSecretKeyHandle;
    // This is the key handle for the AES-GCM secret key.
    type AesGcmKeyHandle;

    // SHA256 related functions.
    /// Init a SHA256 hash context.
    fn sha256_init(ctx: Out<Self::Sha256HashContext>)
        -> CryptoResult<&mut Self::Sha256HashContext>;
    /// Update the hash with `data`.
    fn sha256_update(ctx: &mut Self::Sha256HashContext, data: &[u8]) -> CryptoStatus;
    /// Get the current hash result without finalizing the context. SPDM utilizes
    /// rolling hash a lot.
    fn sha256_get<'a>(
        ctx: &Self::Sha256HashContext,
        buf: Out<'a, Sha256Hash>,
    ) -> CryptoResult<&'a mut Sha256Hash>;
    /// Get the final hash result and destruct the context.
    fn sha256_final(
        ctx: Self::Sha256HashContext,
        buf: Out<Sha256Hash>,
    ) -> CryptoResult<&mut Sha256Hash>;
    /// Perform SHA256 hash in one step.
    fn sha256<'a>(data: &[u8], buf: Out<'a, Sha256Hash>) -> CryptoResult<&'a mut Sha256Hash> {
        let mut ctx = MaybeUninit::<Self::Sha256HashContext>::uninit();
        Self::sha256_init((&mut ctx).into())?;
        // SAFETY: `ctx` is guaranteed to be initialized after a successful
        // `sha256_init`.
        let mut ctx = unsafe { ctx.assume_init() };
        Self::sha256_update(&mut ctx, data)?;
        Self::sha256_final(ctx, buf)
    }

    // ECDSA-P256 related functions. "P256" is stripped from all EC function names
    // to keep them short. P256 is the only curve we use in this implementation.
    /// Perform ECDSA-P256 sign with the identity private key.
    fn ecdsa_sign<'a>(
        key_handle: &Self::IdentityPrivateKeyHandle,
        hash_to_sign: &Sha256Hash,
        buf: Out<'a, EcdsaP256Signature>,
    ) -> CryptoResult<&'a mut EcdsaP256Signature>;
    /// Perform ECDSA-P256 verify with the identity public key.
    fn ecdsa_verify(
        public_key: &IdentityPublicKey,
        hash_to_sign: &Sha256Hash,
        signature: &EcdsaP256Signature,
    ) -> CryptoStatus;

    // HMAC-SHA256 related functions. "SHA256" is stripped from all HMAC function names
    // to keep them short. SHA256 is the only hash algorithm we use in HMAC implementation.
    /// Perform HMAC extract from using `salt` and the shared secret produced by ECDH (P-256).
    /// ECDH is performed using `their_public_key`, and `my_public_key` will be produced. HMAC
    /// extract is only 1 of the 2 steps that need to be performed for a full HKDF, but in SPDM
    /// we separate the 2 steps because SPDM spec reuses the intermediate key to expand into
    /// several other keys.
    fn hmac_extract_from_ecdh<'a, 'b>(
        their_public_key: &EcP256UncompressedPoint,
        salt: &[u8],
        my_public_key: Out<'a, EcP256UncompressedPoint>,
        hmac_derivation_key_handle: Out<'b, Self::HmacDerivationKeyHandle>,
    ) -> CryptoResult<(
        &'a mut EcP256UncompressedPoint,
        &'b mut Self::HmacDerivationKeyHandle,
    )>;
    /// Perform HMAC extract from using `salt` and the shared secret produced by ECDH (P-256).
    /// ECDH is performed using `their_public_key`, and `my_private_key` will be produced. HMAC
    /// extract is only 1 of the 2 steps that need to be performed for a full HKDF, but in SPDM
    /// we separate the 2 steps because SPDM spec reuses the intermediate key to expand into
    /// several other keys.
    fn hmac_extract_from_ecdh_with_priv<'a>(
        their_public_key: &EcP256UncompressedPoint,
        my_private_key: &Self::IdentityPrivateKeyHandle,
        salt: &[u8],
        hmac_derivation_key_handle: Out<'a, Self::HmacDerivationKeyHandle>,
    ) -> CryptoResult<&'a mut Self::HmacDerivationKeyHandle>;
    // Perform HMAC extract from an HMAC derivation handle and data to another hmac derivation
    // handle.
    fn hmac_extract<'a>(
        hmac_derivation_key_handle_in: &Self::HmacDerivationKeyHandle,
        data: &[u8],
        hmac_derivation_key_handle_out: Out<'a, Self::HmacDerivationKeyHandle>,
    ) -> CryptoResult<&'a mut Self::HmacDerivationKeyHandle>;
    /// Perform HMAC expand from using `hmac_derivation_key_handle` and `info`. HMAC
    /// expand uses a secret value as the HMAC key and info as the data to produce
    /// another secret value, pointed by `hmac_secret_key_handle`. It is equivalent
    /// to the first `output_size` bytes of `HMAC(key, info||0x01)` because in SPDM
    /// we always expand to less or equal than the hash size.
    /// This expands into a HMAC secret key which can be used for performing ordinary HMAC.
    fn hmac_expand_hmac_secret_key<'a>(
        hmac_derivation_key_handle: &Self::HmacDerivationKeyHandle,
        info: &[u8],
        hmac_secret_key_handle: Out<'a, Self::HmacSecretKeyHandle>,
    ) -> CryptoResult<&'a mut Self::HmacSecretKeyHandle>;
    /// This expands into another HMAC derivation key.
    fn hmac_expand_derivation_key<'a>(
        hmac_derivation_key_handle_in: &Self::HmacDerivationKeyHandle,
        info: &[u8],
        hmac_derivation_key_handle_out: Out<'a, Self::HmacDerivationKeyHandle>,
    ) -> CryptoResult<&'a mut Self::HmacDerivationKeyHandle>;
    // This expands into an AES-GCM key handle.
    fn hmac_expand_aes_gcm_key<'a>(
        hmac_derivation_key_handle: &Self::HmacDerivationKeyHandle,
        salt: &[u8],
        aes_gcm_key: Out<'a, Self::AesGcmKeyHandle>,
    ) -> CryptoResult<&'a mut Self::AesGcmKeyHandle>;
    // This expands into an AES-GCM IV.
    fn hmac_expand_aes_gcm_iv<'a>(
        hmac_derivation_key_handle: &Self::HmacDerivationKeyHandle,
        salt: &[u8],
        aes_gcm_iv: Out<'a, AesGcm128Iv>,
    ) -> CryptoResult<&'a mut AesGcm128Iv>;
    /// Perform HMAC using `hmac_secret_key_handle` as key and `data` as data.
    fn hmac<'a>(
        hmac_secret_key_handle: &Self::HmacSecretKeyHandle,
        data: &[u8],
        buf: Out<'a, Sha256Hash>,
    ) -> CryptoResult<&'a mut Sha256Hash>;
    /// Validate `hmac` with `hmac_secret_key_handle` as key and `data` as data.
    fn validate_hmac(
        hmac_secret_key_handle: &Self::HmacSecretKeyHandle,
        data: &[u8],
        hmac: &Sha256Hash,
    ) -> CryptoStatus;

    // AES-GCM related functions. We only use AES-GCM-128 in this SPDM implementation.
    /// Encrypts the plaintext into ciphertext and tag. The encryption is performed
    /// in-place, so plaintext and ciphertext share the |buf| buffer.
    fn aes_gcm_encrypt<'a>(
        aes_gcm_key_handle: &Self::AesGcmKeyHandle,
        iv: &AesGcm128Iv,
        aad: &[u8],
        buf: &mut [u8],
        tag: Out<'a, AesGcm128Tag>,
    ) -> CryptoResult<&'a mut AesGcm128Tag>;
    /// Decrypts the ciphertext into plaintext while checking the tag. The decryption
    /// is performed in-place, so plaintext and ciphertext share the |buf| buffer.
    fn aes_gcm_decrypt(
        aes_gcm_key_handle: &Self::AesGcmKeyHandle,
        iv: &AesGcm128Iv,
        aad: &[u8],
        tag: &AesGcm128Tag,
        buf: &mut [u8],
    ) -> CryptoStatus;

    // Misc.
    /// Fill `buf` with random bytes.
    fn random_bytes(buf: Out<[u8]>) -> CryptoResult<&mut [u8]>;
    /// Randomly generate a valid P256 EC key pair.
    fn random_key_pair<'a, 'b>(
        private: Out<'a, Self::IdentityPrivateKeyHandle>,
        public: Out<'b, IdentityPublicKey>,
    ) -> CryptoResult<(
        &'a mut Self::IdentityPrivateKeyHandle,
        &'b mut IdentityPublicKey,
    )>;
}
