// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use uninit::prelude::*;

use crate::types::crypto::{EcdsaP256Signature, Sha256Hash};
use crate::types::error::ErrorCode;

/// In the `Crypto` trait, we only care about success/failure instead of the actual
/// failure status because SPDM error response doesn't have space to propagate
/// different kind of crypto errors. Instead of using `bool` and `Option` as return
/// values, we still want to use status in case we forgot to handle a `false`/`None`
/// return value.
pub struct CryptoError;
pub type CryptoResult<T> = Result<T, CryptoError>;
pub type CryptoStatus = CryptoResult<()>;

impl From<CryptoError> for ErrorCode {
    /// Always default to Unspecified for `Crypto` errors.
    fn from(_value: CryptoError) -> Self {
        ErrorCode::Unspecified
    }
}

/// Crypto trait defines the interface of cryptographic functions and types
/// used in SPDM. Crypto methods should be purely static.
pub trait Crypto {
    type IdentityPrivateKeyHandle;
    /// This is the context object for SHA256 hash operations.
    type Sha256HashContext;

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
}
