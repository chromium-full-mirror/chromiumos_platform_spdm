// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub mod aead;
pub mod key_schedule;
pub mod sign;

#[cfg(feature = "mock")]
use mocktopus::macros::*;
use spdm_types::crypto::{EcdsaP256Signature, Sha256Hash, SHA256_HASH_SIZE};
use spdm_types::deps::{Crypto, IdentityPublicKey};
use uninit::prelude::*;
use zerocopy::AsBytes;

use crate::types::error::{ErrorCode, SpdmStatus};
use crate::types::message::{
    HalfSessionId, SequenceNumber, SessionId, GET_VERSION_REQUEST_SIZE, VERSION_RESPONSE_SIZE,
};

const NEGOTIATION_TRANSCRIPT_SIZE: usize = GET_VERSION_REQUEST_SIZE + VERSION_RESPONSE_SIZE;
pub type NegotiationTranscript = [u8; NEGOTIATION_TRANSCRIPT_SIZE];

const TRANSCRIPT_HASH_SIZE: usize = SHA256_HASH_SIZE;
pub type TranscriptHash = [u8; TRANSCRIPT_HASH_SIZE];

/// Many session functions can be reused for processing a same functionality for
/// a different direction. SpdmRole can be used to specify the direction.
#[derive(Clone, Copy)]
pub enum SpdmRole {
    Requester,
    Responder,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SessionPhase {
    None,
    Handshake,
    Data,
}

pub struct SequenceNumbers {
    pub request: SequenceNumber,
    pub response: SequenceNumber,
}

/// The data constructed/used by session establishment.
pub struct Session<C: Crypto> {
    pub transcript: Option<NegotiationTranscript>,
    pub transcript_hash_ctx: Option<C::Sha256HashContext>,
    pub th1: Option<TranscriptHash>,
    pub th2: Option<TranscriptHash>,
    pub handshake_secret: Option<C::HmacDerivationKeyHandle>,
    pub main_secret: Option<C::HmacDerivationKeyHandle>,
    pub session_id: Option<SessionId>,
    pub requester_public_key: Option<IdentityPublicKey>,
    pub responder_public_key: Option<IdentityPublicKey>,
    pub sequence_numbers: SequenceNumbers,
}

impl<C: Crypto> Default for Session<C> {
    fn default() -> Self {
        Self {
            transcript: None,
            transcript_hash_ctx: None,
            th1: None,
            th2: None,
            handshake_secret: None,
            main_secret: None,
            session_id: None,
            requester_public_key: None,
            responder_public_key: None,
            sequence_numbers: SequenceNumbers {
                request: 0,
                response: 0,
            },
        }
    }
}

#[cfg_attr(feature = "mock", mockable)]
impl<C: Crypto> Session<C> {
    pub fn with_requester_public_key(public_key: &IdentityPublicKey) -> Self {
        Self {
            requester_public_key: Some(public_key.clone()),
            ..Default::default()
        }
    }

    pub fn with_responder_public_key(public_key: &IdentityPublicKey) -> Self {
        Self {
            responder_public_key: Some(public_key.clone()),
            ..Default::default()
        }
    }

    /// Resets the current session.
    pub fn reset_session(&mut self, role: SpdmRole) {
        // The public key of `role` should not be reset.
        let (requester_public_key, responder_public_key) = match role {
            SpdmRole::Requester => (self.requester_public_key.take(), None),
            SpdmRole::Responder => (None, self.responder_public_key.take()),
        };

        *self = Self {
            requester_public_key,
            responder_public_key,
            ..Default::default()
        }
    }

    // Like reset_session, but keep the VCA cache so GetVersion doesn't need to be
    // sent again.
    pub fn reset_session_keep_vca_cache(&mut self, role: SpdmRole) {
        let transcript = self.transcript.take();
        // The public key of `role` should not be reset.
        let (requester_public_key, responder_public_key) = match role {
            SpdmRole::Requester => (self.requester_public_key.take(), None),
            SpdmRole::Responder => (None, self.responder_public_key.take()),
        };

        *self = Self {
            transcript,
            requester_public_key,
            responder_public_key,
            ..Default::default()
        }
    }

    /// Sets the negotiation transcript of the current session. This is the
    /// concatenation of the GetVersion request and the Version response.
    /// The two parameters are only 4 bytes and 8 bytes each, consume them
    /// instead of passing references.
    pub fn set_negotiation_transcript(
        &mut self,
        get_version_request: [u8; GET_VERSION_REQUEST_SIZE],
        version_response: [u8; VERSION_RESPONSE_SIZE],
    ) {
        let mut transcript = [0; NEGOTIATION_TRANSCRIPT_SIZE];
        transcript[0..GET_VERSION_REQUEST_SIZE].copy_from_slice(&get_version_request);
        transcript[GET_VERSION_REQUEST_SIZE..].copy_from_slice(&version_response);
        self.transcript = Some(transcript);
    }

    /// Set the session id.
    pub fn set_session_id(&mut self, requester_half: HalfSessionId, responder_half: HalfSessionId) {
        let mut session_id = [0; 4];
        session_id[0..2].copy_from_slice(&requester_half);
        session_id[2..4].copy_from_slice(&responder_half);
        self.session_id = Some(session_id);
    }

    // Set the requester public key.
    pub fn set_requester_public_key(&mut self, public_key: &IdentityPublicKey) {
        self.requester_public_key = Some(public_key.clone());
    }

    // Set the responder public key.
    pub fn set_responder_public_key(&mut self, public_key: &IdentityPublicKey) {
        self.responder_public_key = Some(public_key.clone());
    }

    // Transcript hash related helper functions.
    pub fn init_transcript_hash_with_key_exchange_request(&mut self, request: &[u8]) -> SpdmStatus {
        let transcript = self.transcript.as_ref().ok_or(ErrorCode::Unspecified)?;
        let public_key = self
            .responder_public_key
            .as_ref()
            .ok_or(ErrorCode::Unspecified)?;

        let mut ctx = MaybeUninit::<C::Sha256HashContext>::uninit();
        C::sha256_init((&mut ctx).into())?;
        // SAFETY: `ctx` is guaranteed to be initialized after a successful
        // `sha256_init`.
        let mut ctx = unsafe { ctx.assume_init() };
        C::sha256_update(&mut ctx, transcript)?;
        let mut key_hash = MaybeUninit::<Sha256Hash>::uninit();
        let key_hash = C::sha256(public_key.as_bytes(), (&mut key_hash).into())?;
        C::sha256_update(&mut ctx, key_hash)?;
        C::sha256_update(&mut ctx, request)?;
        self.transcript_hash_ctx = Some(ctx);
        Ok(())
    }

    pub fn extend_transcript_hash_with_key_exchange_response(
        &mut self,
        response: &[u8],
    ) -> SpdmStatus {
        let ctx = self
            .transcript_hash_ctx
            .as_mut()
            .ok_or(ErrorCode::Unspecified)?;
        C::sha256_update(ctx, response)?;
        Ok(())
    }

    pub fn extend_transcript_hash_with_finish_request(&mut self, request: &[u8]) -> SpdmStatus {
        let ctx = self
            .transcript_hash_ctx
            .as_mut()
            .ok_or(ErrorCode::Unspecified)?;
        let public_key = self
            .requester_public_key
            .as_ref()
            .ok_or(ErrorCode::Unspecified)?;
        let mut key_hash = MaybeUninit::<Sha256Hash>::uninit();
        let key_hash = C::sha256(public_key.as_bytes(), (&mut key_hash).into())?;
        C::sha256_update(ctx, key_hash)?;
        C::sha256_update(ctx, request)?;
        Ok(())
    }

    pub fn extend_transcript_hash_with_key_exchange_signature(
        &mut self,
        signature: &EcdsaP256Signature,
    ) -> SpdmStatus {
        let ctx = self
            .transcript_hash_ctx
            .as_mut()
            .ok_or(ErrorCode::Unspecified)?;
        C::sha256_update(ctx, signature.as_bytes())?;
        // Finalize TH1 here.
        let mut hash = MaybeUninit::<Sha256Hash>::uninit();
        C::sha256_get(ctx, (&mut hash).into())?;
        // SAFETY: `hash` is guaranteed to be initialized after a successful
        // `sha256_get`.
        self.th1 = Some(unsafe { hash.assume_init() });
        Ok(())
    }

    pub fn extend_transcript_hash_with_key_exchange_hmac(
        &mut self,
        hmac: &Sha256Hash,
    ) -> SpdmStatus {
        let ctx = self
            .transcript_hash_ctx
            .as_mut()
            .ok_or(ErrorCode::Unspecified)?;
        C::sha256_update(ctx, hmac)?;
        Ok(())
    }

    pub fn extend_transcript_hash_with_finish_signature(
        &mut self,
        signature: &EcdsaP256Signature,
    ) -> SpdmStatus {
        let ctx = self
            .transcript_hash_ctx
            .as_mut()
            .ok_or(ErrorCode::Unspecified)?;
        C::sha256_update(ctx, signature.as_bytes())?;
        Ok(())
    }

    pub fn extend_transcript_hash_with_finish_hmac(&mut self, hmac: &Sha256Hash) -> SpdmStatus {
        let mut ctx = self
            .transcript_hash_ctx
            .take()
            .ok_or(ErrorCode::Unspecified)?;
        C::sha256_update(&mut ctx, hmac)?;
        let mut hash = MaybeUninit::<Sha256Hash>::uninit();
        C::sha256_final(ctx, (&mut hash).into())?;
        // SAFETY: `hash` is guaranteed to be initialized after a successful
        // `sha256_final`.
        self.th2 = Some(unsafe { hash.assume_init() });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use spdm_test_deps::TestCrypto;

    use super::*;

    #[test]
    fn init_transcript_hash_without_transcript() {
        let key_exchange_request = [0xAA; 8];

        let mut session = Session::<TestCrypto>::default();
        assert_eq!(
            session.init_transcript_hash_with_key_exchange_request(&key_exchange_request),
            Err(ErrorCode::Unspecified)
        );
    }
}
