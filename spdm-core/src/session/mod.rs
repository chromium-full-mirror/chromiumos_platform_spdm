// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

mod key_schedule;
mod sign;

use uninit::prelude::*;
use zerocopy::AsBytes;

use self::key_schedule::{generate_finished_key, generate_message_secrets, MessageSecrets};
use self::sign::make_message_to_sign_for_key_exchange;
use crate::deps::{Crypto, Identity, SpdmDeps};
use crate::types::crypto::{
    EcP256UncompressedPoint, EcdsaP256Signature, Sha256Hash, SHA256_HASH_SIZE,
};
use crate::types::error::{ErrorCode, SpdmResult, SpdmStatus};
use crate::types::message::{
    HalfSessionId, SessionId, GET_VERSION_REQUEST_SIZE, VERSION_RESPONSE_SIZE,
};
use crate::Spdm;

const NEGOTIATION_TRANSCRIPT_SIZE: usize = GET_VERSION_REQUEST_SIZE + VERSION_RESPONSE_SIZE;
pub type NegotiationTranscript = [u8; NEGOTIATION_TRANSCRIPT_SIZE];

const TRANSCRIPT_HASH_SIZE: usize = SHA256_HASH_SIZE;
pub type TranscriptHash = [u8; TRANSCRIPT_HASH_SIZE];

/// Many sessions functions can be reused for processing a same functionality for
/// a different direction. SpdmRole can be used to specify the direction.
#[derive(Clone, Copy)]
pub enum SpdmRole {
    Requester,
    // LINT: We'll use Responder soon, add it here first for symmetricity.
    #[allow(dead_code)]
    Responder,
}

#[derive(Clone, Copy)]
pub enum SessionPhase {
    Handshake,
}

/// The data constructed/used by session establishment.
pub struct Session<C: Crypto> {
    pub transcript: Option<NegotiationTranscript>,
    pub transcript_hash_ctx: Option<C::Sha256HashContext>,
    pub th1: Option<TranscriptHash>,
    pub handshake_secret: Option<C::HmacDerivationKeyHandle>,
    pub session_id: Option<SessionId>,
}

impl<C: Crypto> Default for Session<C> {
    fn default() -> Self {
        Self {
            transcript: None,
            transcript_hash_ctx: None,
            th1: None,
            handshake_secret: None,
            session_id: None,
        }
    }
}

/// Defines the methods related to session handling.
///
/// This trait is only used for separating impl blocks of `Spdm` struct by functionality.
pub trait SpdmSessionManager {
    /// Resets the current session.
    fn reset_session(&mut self);

    // Like reset_session, but keep the VCA cache so GetVersion doesn't need to be
    // sent again.
    fn reset_session_keep_vca_cache(&mut self);

    /// Sets the negotiation transcript of the current session. This is the
    /// concatenation of the GetVersion request and the Version response.
    /// The two parameters are only 4 bytes and 8 bytes each, consume them
    /// instead of passing references.
    fn set_negotiation_transcript(
        &mut self,
        get_version_request: [u8; GET_VERSION_REQUEST_SIZE],
        version_response: [u8; VERSION_RESPONSE_SIZE],
    );

    /// Set the session id.
    fn set_session_id(&mut self, requester_half: HalfSessionId, responder_half: HalfSessionId);

    // Perform ECDHE, return the resulting public key, and store the generated derivation key.
    fn generate_handshake_secret<'a>(
        &mut self,
        their_public_key: &EcP256UncompressedPoint,
        my_public_key: &'a mut MaybeUninit<EcP256UncompressedPoint>,
    ) -> SpdmResult<&'a mut EcP256UncompressedPoint>;

    // Transcript hash related helper functions.
    fn init_transcript_hash_with_key_exchange_request(&mut self, request: &[u8]) -> SpdmStatus;
    fn extend_transcript_hash_with_key_exchange_response(&mut self, response: &[u8]) -> SpdmStatus;

    /// Signs the key exchange message.
    fn sign_key_exchange_message(&mut self, buf: &mut EcdsaP256Signature) -> SpdmStatus;

    /// Hmacs the key exchange message, including the signature part.
    fn hmac_key_exchange_message(&mut self, buf: &mut Sha256Hash) -> SpdmStatus;
}

impl<D: SpdmDeps> SpdmSessionManager for Spdm<D> {
    fn reset_session(&mut self) {
        self.session = Session::default();
    }

    fn reset_session_keep_vca_cache(&mut self) {
        let transcript = self.session.transcript;
        self.session = Session::default();
        self.session.transcript = transcript;
    }

    fn set_negotiation_transcript(
        &mut self,
        get_version_request: [u8; GET_VERSION_REQUEST_SIZE],
        version_response: [u8; VERSION_RESPONSE_SIZE],
    ) {
        let mut transcript = [0; NEGOTIATION_TRANSCRIPT_SIZE];
        transcript[0..GET_VERSION_REQUEST_SIZE].copy_from_slice(&get_version_request);
        transcript[GET_VERSION_REQUEST_SIZE..].copy_from_slice(&version_response);
        self.session.transcript = Some(transcript);
    }

    fn set_session_id(&mut self, requester_half: HalfSessionId, responder_half: HalfSessionId) {
        let mut session_id = [0; 4];
        session_id[0..2].copy_from_slice(&requester_half);
        session_id[2..4].copy_from_slice(&responder_half);
        self.session.session_id = Some(session_id);
    }

    fn generate_handshake_secret<'a>(
        &mut self,
        their_public_key: &EcP256UncompressedPoint,
        my_public_key: &'a mut MaybeUninit<EcP256UncompressedPoint>,
    ) -> SpdmResult<&'a mut EcP256UncompressedPoint> {
        const SALT_0: [u8; SHA256_HASH_SIZE] = [0; SHA256_HASH_SIZE];
        let mut handle = MaybeUninit::<<D::Crypto as Crypto>::HmacDerivationKeyHandle>::uninit();
        let (my_public_key, _) = D::Crypto::hmac_extract_from_ecdh(
            their_public_key,
            &SALT_0,
            my_public_key.as_out(),
            (&mut handle).into(),
        )?;
        // SAFETY: `handle` is guaranteed to be initialized after a successful
        // `hmac_extract_from_ecdh`.
        self.session.handshake_secret = unsafe { Some(handle.assume_init()) };
        Ok(my_public_key)
    }

    fn init_transcript_hash_with_key_exchange_request(&mut self, request: &[u8]) -> SpdmStatus {
        let transcript = self
            .session
            .transcript
            .as_ref()
            .ok_or(ErrorCode::Unspecified)?;

        let mut ctx = MaybeUninit::<<D::Crypto as Crypto>::Sha256HashContext>::uninit();
        D::Crypto::sha256_init((&mut ctx).into())?;
        // SAFETY: `ctx` is guaranteed to be initialized after a successful
        // `sha256_init`.
        let mut ctx = unsafe { ctx.assume_init() };
        D::Crypto::sha256_update(&mut ctx, transcript)?;
        let mut key_hash = MaybeUninit::<Sha256Hash>::uninit();
        let key_hash = D::Crypto::sha256(
            self.identity.identity_public_key().as_bytes(),
            (&mut key_hash).into(),
        )?;
        D::Crypto::sha256_update(&mut ctx, key_hash)?;
        D::Crypto::sha256_update(&mut ctx, request)?;
        self.session.transcript_hash_ctx = Some(ctx);
        Ok(())
    }

    fn extend_transcript_hash_with_key_exchange_response(&mut self, response: &[u8]) -> SpdmStatus {
        let ctx = self
            .session
            .transcript_hash_ctx
            .as_mut()
            .ok_or(ErrorCode::Unspecified)?;
        D::Crypto::sha256_update(ctx, response)?;
        Ok(())
    }

    fn sign_key_exchange_message(&mut self, buf: &mut EcdsaP256Signature) -> SpdmStatus {
        let ctx = self
            .session
            .transcript_hash_ctx
            .as_ref()
            .ok_or(ErrorCode::Unspecified)?;

        let mut transcipt_hash = MaybeUninit::<Sha256Hash>::uninit();
        let transcipt_hash = D::Crypto::sha256_get(ctx, (&mut transcipt_hash).into())?;

        let mut hash_to_sign = MaybeUninit::<Sha256Hash>::uninit();
        let hash_to_sign = make_message_to_sign_for_key_exchange::<D::Crypto>(
            transcipt_hash,
            (&mut hash_to_sign).into(),
        )?;
        let sig = D::Crypto::ecdsa_sign(
            self.identity.identity_private_key_handle(),
            hash_to_sign,
            buf.manually_drop_mut().into(),
        )?;
        // Update the transcript after signing.
        self.extend_transcript_hash_with_key_exchange_signature(sig)?;
        Ok(())
    }

    fn hmac_key_exchange_message(&mut self, buf: &mut Sha256Hash) -> SpdmStatus {
        let mut message_secrets = MaybeUninit::<MessageSecrets<D::Crypto>>::uninit();
        let secrets = generate_message_secrets(
            &self.session,
            SessionPhase::Handshake,
            (&mut message_secrets).into(),
        )?;
        let th1 = self.session.th1.as_ref().ok_or(ErrorCode::Unspecified)?;
        let mut finished_key = MaybeUninit::<<D::Crypto as Crypto>::HmacSecretKeyHandle>::uninit();
        let finished_key =
            generate_finished_key(SpdmRole::Responder, secrets, (&mut finished_key).into())?;
        D::Crypto::hmac(finished_key, th1, buf.into())?;
        Ok(())
    }
}

/// Defines the private methods related to session handling.
///
/// This trait is only used for separating impl blocks of `Spdm` struct by functionality.
trait SpdmSessionManagerPrivate {
    // Transcript hash related helper functions.
    fn extend_transcript_hash_with_key_exchange_signature(
        &mut self,
        signature: &EcdsaP256Signature,
    ) -> SpdmStatus;
    fn extend_transcript_hash_with_key_exchange_hmac(&mut self, hmac: &[u8]) -> SpdmStatus;
}

impl<D: SpdmDeps> SpdmSessionManagerPrivate for Spdm<D> {
    fn extend_transcript_hash_with_key_exchange_signature(
        &mut self,
        signature: &EcdsaP256Signature,
    ) -> SpdmStatus {
        let ctx = self
            .session
            .transcript_hash_ctx
            .as_mut()
            .ok_or(ErrorCode::Unspecified)?;
        D::Crypto::sha256_update(ctx, signature.as_bytes())?;
        // Finalize TH1 here.
        let mut hash = MaybeUninit::<Sha256Hash>::uninit();
        D::Crypto::sha256_get(ctx, (&mut hash).into())?;
        // SAFETY: `hash` is guaranteed to be initialized after a successful
        // `sha256_get`.
        self.session.th1 = Some(unsafe { hash.assume_init() });
        Ok(())
    }
    fn extend_transcript_hash_with_key_exchange_hmac(&mut self, hmac: &[u8]) -> SpdmStatus {
        let ctx = self
            .session
            .transcript_hash_ctx
            .as_mut()
            .ok_or(ErrorCode::Unspecified)?;
        D::Crypto::sha256_update(ctx, hmac)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use zerocopy::FromBytes;

    use super::*;
    use crate::deps::{SpdmTestDeps, TestIdentity};

    #[test]
    fn init_transcript_and_sign() {
        let get_version_request = [0xAA; 4];
        let version_response = [0xBB; 8];
        let key_exchange_request = [0xAA; 8];
        let key_exchange_response = [0xBB; 16];
        let mut signature = EcdsaP256Signature::new_zeroed();

        let mut spdm = Spdm::<SpdmTestDeps>::new(TestIdentity);
        spdm.set_negotiation_transcript(get_version_request, version_response);
        assert!(spdm
            .init_transcript_hash_with_key_exchange_request(&key_exchange_request)
            .is_ok());
        // Caveat: The current implementation isn't capable of checking whether hash is
        // extended with the key exchange response before signing. We might need to
        // introduce more state if we want this enforcement.
        assert!(spdm
            .extend_transcript_hash_with_key_exchange_response(&key_exchange_response)
            .is_ok());
        assert!(spdm.sign_key_exchange_message(&mut signature).is_ok());
    }

    #[test]
    fn init_transcript_hash_without_transcript() {
        let key_exchange_request = [0xAA; 8];

        let mut spdm = Spdm::<SpdmTestDeps>::new(TestIdentity);
        assert_eq!(
            spdm.init_transcript_hash_with_key_exchange_request(&key_exchange_request),
            Err(ErrorCode::Unspecified)
        );
    }

    #[test]
    fn sign_without_transcript_hash() {
        let mut signature = EcdsaP256Signature::new_zeroed();

        let mut spdm = Spdm::<SpdmTestDeps>::new(TestIdentity);
        assert_eq!(
            spdm.sign_key_exchange_message(&mut signature),
            Err(ErrorCode::Unspecified)
        );
    }
}
