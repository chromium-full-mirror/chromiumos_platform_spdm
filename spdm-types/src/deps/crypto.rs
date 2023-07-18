// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use uninit::prelude::*;

use crate::crypto::{EcP256UncompressedPoint, EcdsaP256Signature, Sha256Hash};

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
pub trait Crypto {
    type IdentityPrivateKeyHandle;
    /// This is the context object for SHA256 hash operations.
    type Sha256HashContext;
    /// This is the key produced by HMAC-extract which needs to go through HMAC-expand
    /// before being used.
    type HmacDerivationKeyHandle;
    /// This is the key handle for secrets that can be used to perform ordinary
    /// HMACs.
    type HmacSecretKeyHandle;

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
    /// Perform HMAC expand from using `hmac_derivation_key_handle` and `info`. HMAC
    /// expand uses a secret value as the HMAC key and info as the data to produce
    /// another secret value, pointed by `hmac_secret_key_handle`. It is equivalent
    /// to the first `output_size` bytes of `HMAC(key, info||0x00)` because in SPDM
    /// we always expand to less than the hash size.
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
    /// Perform HMAC using `hmac_secret_key_handle` as key and `data` as data.
    fn hmac<'a>(
        hmac_secret_key_handle: &Self::HmacSecretKeyHandle,
        data: &[u8],
        buf: Out<'a, Sha256Hash>,
    ) -> CryptoResult<&'a mut Sha256Hash>;

    // Misc.
    /// Fill `buf` with random bytes.
    fn random_bytes(buf: Out<[u8]>) -> CryptoResult<&mut [u8]>;
}
