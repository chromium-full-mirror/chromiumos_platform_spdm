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
use spdm::types::error::{ErrorCode, SpdmResult, SpdmStatus};
use spdm_proc_macros::{cfg_test_mock, cfg_test_mockable};
use spdm_types::crypto::{
    EcP256UncompressedPoint, EcdsaP256Signature, Sha256Hash, SHA256_HASH_SIZE,
};
use spdm_types::deps::Crypto;
use uninit::prelude::*;

// Provide some extra responder-only utils to the Session struct.
pub trait ResponderSession<C: Crypto> {
    // Perform ECDHE, return the resulting public key, and store the generated derivation key.
    fn generate_handshake_secret<'a>(
        &mut self,
        their_public_key: &EcP256UncompressedPoint,
        my_public_key: &'a mut MaybeUninit<EcP256UncompressedPoint>,
    ) -> SpdmResult<&'a mut EcP256UncompressedPoint>;

    /// Signs the key exchange message.
    fn sign_key_exchange_message(
        &mut self,
        private_key_handle: &C::IdentityPrivateKeyHandle,
        buf: &mut EcdsaP256Signature,
    ) -> SpdmStatus;

    /// Hmacs the key exchange message, including the signature part.
    fn hmac_key_exchange_message(&mut self, buf: &mut Sha256Hash) -> SpdmStatus;

    /// Verifies the signature provided in the finish message.
    fn verify_finish_message(&mut self, signature: &EcdsaP256Signature) -> SpdmStatus;

    /// Validates the hmac provided in the finish message.
    fn validate_finish_message_hmac(&mut self, hmac: &Sha256Hash) -> SpdmStatus;
}

#[cfg_test_mockable]
impl<C: Crypto> ResponderSession<C> for Session<C> {
    fn generate_handshake_secret<'a>(
        &mut self,
        their_public_key: &EcP256UncompressedPoint,
        my_public_key: &'a mut MaybeUninit<EcP256UncompressedPoint>,
    ) -> SpdmResult<&'a mut EcP256UncompressedPoint> {
        const SALT_0: [u8; SHA256_HASH_SIZE] = [0; SHA256_HASH_SIZE];
        let mut handshale_secret = MaybeUninit::<C::HmacDerivationKeyHandle>::uninit();
        let (my_public_key, _) = C::hmac_extract_from_ecdh(
            their_public_key,
            &SALT_0,
            my_public_key.as_out(),
            (&mut handshale_secret).into(),
        )?;
        // SAFETY: `handshale_secret` is guaranteed to be initialized after a successful
        // `hmac_extract_from_ecdh`.
        self.handshake_secret = unsafe { Some(handshale_secret.assume_init()) };

        let mut main_secret = MaybeUninit::<C::HmacDerivationKeyHandle>::uninit();
        generate_main_secret::<C>(
            self.handshake_secret.as_ref().unwrap(),
            main_secret.as_out(),
        )?;
        // SAFETY: `main_secret` is guaranteed to be initialized after a successful
        // `generate_main_secret`.
        self.main_secret = unsafe { Some(main_secret.assume_init()) };
        Ok(my_public_key)
    }

    fn sign_key_exchange_message(
        &mut self,
        private_key_handle: &C::IdentityPrivateKeyHandle,
        buf: &mut EcdsaP256Signature,
    ) -> SpdmStatus {
        let ctx = self
            .transcript_hash_ctx
            .as_ref()
            .ok_or(ErrorCode::Unspecified)?;

        let mut transcipt_hash = MaybeUninit::<Sha256Hash>::uninit();
        let transcipt_hash: &_ = C::sha256_get(ctx, (&mut transcipt_hash).into())?;

        let mut hash_to_sign = MaybeUninit::<Sha256Hash>::uninit();
        let hash_to_sign =
            make_message_to_sign_for_key_exchange::<C>(transcipt_hash, (&mut hash_to_sign).into())?;
        let sig = C::ecdsa_sign(
            private_key_handle,
            hash_to_sign,
            buf.manually_drop_mut().into(),
        )?;
        // Update the transcript after signing.
        self.extend_transcript_hash_with_key_exchange_signature(sig)?;
        Ok(())
    }

    fn hmac_key_exchange_message(&mut self, buf: &mut Sha256Hash) -> SpdmStatus {
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
        C::hmac(&finished_key, th1, buf.into())?;
        self.extend_transcript_hash_with_key_exchange_hmac(buf)?;
        Ok(())
    }

    fn verify_finish_message(&mut self, signature: &EcdsaP256Signature) -> SpdmStatus {
        let ctx = self
            .transcript_hash_ctx
            .as_ref()
            .ok_or(ErrorCode::Unspecified)?;
        let public_key = self
            .requester_public_key
            .as_ref()
            .ok_or(ErrorCode::Unspecified)?;

        let mut transcipt_hash = MaybeUninit::<Sha256Hash>::uninit();
        let transcipt_hash: &_ = C::sha256_get(ctx, (&mut transcipt_hash).into())?;

        let mut hash_to_sign = MaybeUninit::<Sha256Hash>::uninit();
        let hash_to_sign =
            make_message_to_sign_for_finish::<C>(transcipt_hash, (&mut hash_to_sign).into())?;
        C::ecdsa_verify(public_key, hash_to_sign, signature)?;
        // Update the transcript after verifying.
        self.extend_transcript_hash_with_finish_signature(signature)?;
        Ok(())
    }

    fn validate_finish_message_hmac(&mut self, hmac: &Sha256Hash) -> SpdmStatus {
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
        C::validate_hmac(&finished_key, transcipt_hash, hmac)?;
        self.extend_transcript_hash_with_finish_hmac(hmac)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use spdm_test_deps::{TestIdentity, TestVendor};
    use spdm_types::deps::Identity;
    use zerocopy::FromBytes;

    use super::*;
    use crate::test::TestResponderDeps;
    use crate::Responder;

    #[test]
    fn init_transcript_and_sign() {
        let get_version_request = [0xAA; 4];
        let version_response = [0xBB; 8];
        let key_exchange_request = [0xAA; 8];
        let key_exchange_response = [0xBB; 16];
        let mut signature = EcdsaP256Signature::new_zeroed();

        let mut spdm = Responder::<TestResponderDeps>::new(TestIdentity, TestVendor);
        spdm.session
            .set_negotiation_transcript(get_version_request, version_response);
        assert!(spdm
            .session
            .init_transcript_hash_with_key_exchange_request(&key_exchange_request)
            .is_ok());
        // Caveat: The current implementation isn't capable of checking whether hash is
        // extended with the key exchange response before signing. We might need to
        // introduce more state if we want this enforcement.
        assert!(spdm
            .session
            .extend_transcript_hash_with_key_exchange_response(&key_exchange_response)
            .is_ok());
        assert!(spdm
            .session
            .sign_key_exchange_message(spdm.identity.identity_private_key_handle(), &mut signature)
            .is_ok());
    }

    #[test]
    fn sign_without_transcript_hash() {
        let mut signature = EcdsaP256Signature::new_zeroed();

        let mut spdm = Responder::<TestResponderDeps>::new(TestIdentity, TestVendor);
        assert_eq!(
            spdm.session.sign_key_exchange_message(
                spdm.identity.identity_private_key_handle(),
                &mut signature
            ),
            Err(ErrorCode::Unspecified)
        );
    }
}
