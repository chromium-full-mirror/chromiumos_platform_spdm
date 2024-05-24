// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[cfg_test_mock]
use mocktopus::macros::*;
use spdm::session::key_schedule::{
    generate_finished_key, generate_main_secret, generate_message_secrets, MessageSecrets,
};
use spdm::session::sign::{make_message_to_sign_for_finish, make_message_to_sign_for_key_exchange};
use spdm::session::{Session, SessionPhase, SpdmRole};
use spdm::types::error::{ErrorCode, SpdmStatus};
use spdm_proc_macros::{cfg_test_mock, cfg_test_mockable};
use spdm_types::crypto::{
    EcP256UncompressedPoint, EcdsaP256Signature, Sha256Hash, SHA256_HASH_SIZE,
};
use spdm_types::deps::Crypto;
use uninit::prelude::*;

// Provide some extra requester-only utils to the Session struct.
pub trait RequesterSession<C: Crypto> {
    // Perform ECDHE and store the generated derivation key.
    fn generate_handshake_secret(
        &mut self,
        their_public_key: &EcP256UncompressedPoint,
        my_private_key: &C::IdentityPrivateKeyHandle,
    ) -> SpdmStatus;

    /// Verifies the key exchange message signature.
    fn verify_key_exchange_message(&mut self, signature: &EcdsaP256Signature) -> SpdmStatus;

    /// Verifies the key exchange message hmac.
    fn verify_key_exchange_message_hmac(&mut self, hmac: &Sha256Hash) -> SpdmStatus;

    /// Signs the finish message.
    fn sign_finish_message(
        &mut self,
        private_key_handle: &C::IdentityPrivateKeyHandle,
        signature: &mut EcdsaP256Signature,
    ) -> SpdmStatus;

    /// Hmacs the finish message, including the signature part.
    fn hmac_finish_message(&mut self, hmac: &mut Sha256Hash) -> SpdmStatus;
}

#[cfg_test_mockable]
impl<C: Crypto> RequesterSession<C> for Session<C> {
    fn generate_handshake_secret(
        &mut self,
        their_public_key: &EcP256UncompressedPoint,
        my_private_key: &C::IdentityPrivateKeyHandle,
    ) -> SpdmStatus {
        const SALT_0: [u8; SHA256_HASH_SIZE] = [0; SHA256_HASH_SIZE];
        let mut handshake_secret = MaybeUninit::<C::HmacDerivationKeyHandle>::uninit();
        C::hmac_extract_from_ecdh_with_priv(
            their_public_key,
            my_private_key,
            &SALT_0,
            (&mut handshake_secret).into(),
        )?;
        // SAFETY: `handshake_secret` is guaranteed to be initialized after a successful
        // `hmac_extract_from_ecdh`.
        self.handshake_secret = unsafe { Some(handshake_secret.assume_init()) };

        let mut main_secret = MaybeUninit::<C::HmacDerivationKeyHandle>::uninit();
        generate_main_secret::<C>(
            self.handshake_secret.as_ref().unwrap(),
            main_secret.as_out(),
        )?;
        // SAFETY: `main_secret` is guaranteed to be initialized after a successful
        // `generate_main_secret`.
        self.main_secret = unsafe { Some(main_secret.assume_init()) };
        Ok(())
    }

    fn verify_key_exchange_message(&mut self, signature: &EcdsaP256Signature) -> SpdmStatus {
        let ctx = self
            .transcript_hash_ctx
            .as_ref()
            .ok_or(ErrorCode::Unspecified)?;
        let public_key = self
            .responder_public_key
            .as_ref()
            .ok_or(ErrorCode::Unspecified)?;

        let mut transcipt_hash = MaybeUninit::<Sha256Hash>::uninit();
        let transcipt_hash: &_ = C::sha256_get(ctx, (&mut transcipt_hash).into())?;

        let mut hash_to_sign = MaybeUninit::<Sha256Hash>::uninit();
        let hash_to_sign =
            make_message_to_sign_for_key_exchange::<C>(transcipt_hash, (&mut hash_to_sign).into())?;
        C::ecdsa_verify(public_key, hash_to_sign, signature)?;
        // Update the transcript after verifying.
        self.extend_transcript_hash_with_key_exchange_signature(signature)?;
        Ok(())
    }

    fn verify_key_exchange_message_hmac(&mut self, hmac: &Sha256Hash) -> SpdmStatus {
        let mut message_secrets = MaybeUninit::<MessageSecrets<C>>::uninit();
        generate_message_secrets(self, SessionPhase::Handshake, (&mut message_secrets).into())?;
        // SAFETY: `message_secrets` is guaranteed to be initialized after a successful
        // `generate_message_secrets`.
        let secrets = unsafe { message_secrets.assume_init() };

        let th1 = self.th1.as_ref().ok_or(ErrorCode::Unspecified)?;
        let mut finished_key = MaybeUninit::<<C as Crypto>::HmacSecretKeyHandle>::uninit();
        generate_finished_key(SpdmRole::Responder, &secrets, (&mut finished_key).into())?;
        // SAFETY: `finished_key` is guaranteed to be initialized after a successful
        // `generate_finished_key`.
        let finished_key = unsafe { finished_key.assume_init() };
        C::validate_hmac(&finished_key, th1, hmac)?;
        // Update the transcript after verifying.
        self.extend_transcript_hash_with_key_exchange_hmac(hmac)?;
        Ok(())
    }

    fn sign_finish_message(
        &mut self,
        private_key_handle: &C::IdentityPrivateKeyHandle,
        signature: &mut EcdsaP256Signature,
    ) -> SpdmStatus {
        let ctx = self
            .transcript_hash_ctx
            .as_ref()
            .ok_or(ErrorCode::Unspecified)?;

        let mut transcipt_hash = MaybeUninit::<Sha256Hash>::uninit();
        let transcipt_hash: &_ = C::sha256_get(ctx, (&mut transcipt_hash).into())?;

        let mut hash_to_sign = MaybeUninit::<Sha256Hash>::uninit();
        let hash_to_sign =
            make_message_to_sign_for_finish::<C>(transcipt_hash, (&mut hash_to_sign).into())?;
        C::ecdsa_sign(
            private_key_handle,
            hash_to_sign,
            signature.manually_drop_mut().into(),
        )?;
        // Update the transcript after verifying.
        self.extend_transcript_hash_with_finish_signature(signature)?;
        Ok(())
    }

    fn hmac_finish_message(&mut self, hmac: &mut Sha256Hash) -> SpdmStatus {
        let ctx = self
            .transcript_hash_ctx
            .as_ref()
            .ok_or(ErrorCode::Unspecified)?;

        let mut message_secrets = MaybeUninit::<MessageSecrets<C>>::uninit();
        generate_message_secrets(self, SessionPhase::Handshake, (&mut message_secrets).into())?;
        // SAFETY: `message_secrets` is guaranteed to be initialized after a successful
        // `generate_message_secrets`.
        let secrets = unsafe { message_secrets.assume_init() };

        let mut transcipt_hash = MaybeUninit::<Sha256Hash>::uninit();
        let transcipt_hash: &_ = C::sha256_get(ctx, (&mut transcipt_hash).into())?;

        let mut finished_key = MaybeUninit::<<C as Crypto>::HmacSecretKeyHandle>::uninit();
        generate_finished_key(SpdmRole::Requester, &secrets, (&mut finished_key).into())?;
        // SAFETY: `finished_key` is guaranteed to be initialized after a successful
        // `generate_finished_key`.
        let finished_key = unsafe { finished_key.assume_init() };
        C::hmac(&finished_key, transcipt_hash, hmac.into())?;
        self.extend_transcript_hash_with_finish_hmac(hmac)?;
        Ok(())
    }
}
