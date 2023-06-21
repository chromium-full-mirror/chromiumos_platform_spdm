// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::deps::SpdmDeps;
use crate::types::message::{GET_VERSION_REQUEST_SIZE, VERSION_RESPONSE_SIZE};
use crate::Spdm;

const NEGOTIATION_TRANSCRIPT_SIZE: usize = GET_VERSION_REQUEST_SIZE + VERSION_RESPONSE_SIZE;
pub type NegotiationTranscript = [u8; NEGOTIATION_TRANSCRIPT_SIZE];

/// The data constructed/used by session establishment.
#[derive(Default)]
pub struct Session {
    pub transcript: Option<NegotiationTranscript>,
}

/// Defines the methods related to session handling.
///
/// This trait is only used for separating impl blocks of `Spdm` struct by functionality.
pub trait SpdmSessionManager {
    /// Resets the current session.
    fn reset_session(&mut self);

    /// Sets the negotiation transcript of the current session. This is the
    /// concatenation of the GetVersion request and the Version response.
    /// The two parameters are only 4 bytes and 8 bytes each, consume them
    /// instead of passing references.
    fn set_negotiation_transcript(
        &mut self,
        get_version_request: [u8; GET_VERSION_REQUEST_SIZE],
        version_response: [u8; VERSION_RESPONSE_SIZE],
    );
}

impl<D: SpdmDeps> SpdmSessionManager for Spdm<D> {
    fn reset_session(&mut self) {
        self.session = Session::default();
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
}
