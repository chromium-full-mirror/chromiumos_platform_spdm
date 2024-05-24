// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::iter::repeat;

use spdm_types::crypto::Sha256Hash;
use spdm_types::deps::Crypto;
use uninit::prelude::*;

use super::SpdmRole;
use crate::types::error::{ErrorCode, SpdmResult};

const COMBINED_PREFIX_SIZE: usize = 100;
const PREFIX_VERSION_STR: &str = "dmtf-spdm-v1.3.*";
const REPEATS: usize = 4;
const PREFIX_VERSION_LENGTH: usize = REPEATS * PREFIX_VERSION_STR.len();

const CONTEXT_PREFIX_SIZE: usize = 10;
const REQUESTER_CONTEXT_PREFIX: &str = "requester-";
const RESPONDER_CONTEXT_PREFIX: &str = "responder-";
const _: () = assert!(REQUESTER_CONTEXT_PREFIX.len() == CONTEXT_PREFIX_SIZE);
const _: () = assert!(RESPONDER_CONTEXT_PREFIX.len() == CONTEXT_PREFIX_SIZE);

const KEY_EXCHANGE_RESPONSE_SIGNING_CONTEXT: &str = "key_exchange_rsp signing";
const FINISH_SIGNING_CONTEXT: &str = "finish signing";

fn context_prefix(role: SpdmRole) -> &'static str {
    match role {
        SpdmRole::Requester => REQUESTER_CONTEXT_PREFIX,
        SpdmRole::Responder => RESPONDER_CONTEXT_PREFIX,
    }
}

/// The actual message to sign is `SHA256(prefix||hash)`, where `prefix` is a
/// 100-byte buffer that:
/// 1. Starts with "dmtf-spdm-v1.3.*" 4 times.
/// 2. Ends with "requester-`context`" or "responder-`context`" based on `role`.
/// 3. Zero for all other bytes (at least 1).
fn make_prefix<'a>(role: SpdmRole, context: &str, buf: Out<'a, [u8]>) -> SpdmResult<&'a mut [u8]> {
    if PREFIX_VERSION_LENGTH + CONTEXT_PREFIX_SIZE + context.len() + 1 > COMBINED_PREFIX_SIZE {
        return Err(ErrorCode::Unspecified);
    }
    // Unfilled positions in the middle will be zero-padded according to the spec,
    // so let's just initialize it with zeroes.
    let buf = buf.fill_with_iter(repeat(0));
    for i in (0..PREFIX_VERSION_LENGTH).step_by(PREFIX_VERSION_STR.len()) {
        buf[i..i + PREFIX_VERSION_STR.len()].copy_from_slice(PREFIX_VERSION_STR.as_bytes());
    }
    let context_prefix = context_prefix(role);
    let context_offset = COMBINED_PREFIX_SIZE - context.len();
    buf[context_offset..].copy_from_slice(context.as_bytes());
    buf[context_offset - context_prefix.len()..context_offset]
        .copy_from_slice(context_prefix.as_bytes());
    Ok(buf)
}

/// See [`make_prefix`](`make_prefix`).
// SAFETY: `buf` is guaranteed to be initialized if `Ok` is returned.
fn make_message_to_sign<'a, C: Crypto>(
    role: SpdmRole,
    context: &str,
    hash: &Sha256Hash,
    buf: Out<'a, Sha256Hash>,
) -> SpdmResult<&'a mut Sha256Hash> {
    let mut combined_prefix = uninit_array![u8; COMBINED_PREFIX_SIZE];
    let combined_prefix = make_prefix(role, context, combined_prefix.as_mut().into())?;

    let mut hash_ctx = MaybeUninit::<C::Sha256HashContext>::uninit();
    C::sha256_init((&mut hash_ctx).into())?;
    // SAFETY: `hash_ctx` is guaranteed to be initialized after a successful
    // `sha256_init`.
    let mut hash_ctx = unsafe { hash_ctx.assume_init() };
    C::sha256_update(&mut hash_ctx, combined_prefix)?;
    C::sha256_update(&mut hash_ctx, hash)?;
    Ok(C::sha256_final(hash_ctx, buf)?)
}

// SAFETY: `buf` is guaranteed to be initialized if `Ok` is returned.
pub fn make_message_to_sign_for_key_exchange<'a, C: Crypto>(
    transcript_hash: &Sha256Hash,
    buf: Out<'a, Sha256Hash>,
) -> SpdmResult<&'a mut Sha256Hash> {
    make_message_to_sign::<C>(
        SpdmRole::Requester,
        KEY_EXCHANGE_RESPONSE_SIGNING_CONTEXT,
        transcript_hash,
        buf,
    )
}

// SAFETY: `buf` is guaranteed to be initialized if `Ok` is returned.
pub fn make_message_to_sign_for_finish<'a, C: Crypto>(
    transcript_hash: &Sha256Hash,
    buf: Out<'a, Sha256Hash>,
) -> SpdmResult<&'a mut Sha256Hash> {
    make_message_to_sign::<C>(
        SpdmRole::Responder,
        FINISH_SIGNING_CONTEXT,
        transcript_hash,
        buf,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_prefix() {
        let mut buf = uninit_array![u8; 100];
        let buf = match make_prefix(SpdmRole::Requester, "abc", buf.as_mut().into()) {
            Ok(b) => b,
            Err(err) => panic!("{err:?}"),
        };

        let mut expected_prefix = vec![];
        expected_prefix.extend_from_slice("dmtf-spdm-v1.3.*".as_bytes());
        expected_prefix.extend_from_slice("dmtf-spdm-v1.3.*".as_bytes());
        expected_prefix.extend_from_slice("dmtf-spdm-v1.3.*".as_bytes());
        expected_prefix.extend_from_slice("dmtf-spdm-v1.3.*".as_bytes());
        const PAD_SIZE: usize = 36 - CONTEXT_PREFIX_SIZE - 3;
        expected_prefix.extend_from_slice(&[0; PAD_SIZE]);
        expected_prefix.extend_from_slice("requester-abc".as_bytes());
        assert_eq!(buf, expected_prefix);
    }
}
