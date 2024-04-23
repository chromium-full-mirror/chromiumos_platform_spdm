// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use spdm_types::crypto::{AesGcm128Tag, AES_GCM_128_TAG_SIZE};
use spdm_types::deps::Crypto;
use uninit::prelude::*;

use super::key_schedule::AeadKeys;
use crate::types::error::{ErrorCode, SpdmResult};
use crate::types::message::SessionId;

// Session ID + Length + Application data length + GCM tag.
const MINIMUM_SECURE_MESSAGE_LENGTH: usize = 24;
const LENGTH_OFFSET: usize = 4;
const CIPHERTEXT_OFFSET: usize = 6;
pub const REQUEST_OFFSET: usize = 8;

/// The message format of a SPDM secure message is:
///
/// | Byte offset | Size (bytes) | Field               | Description          |
/// | :---------- | :----------- | :------------------ | :------------------- |
/// | 0           | 4            | SessionId           |                      |
/// | 4           | 2            | Length              | Remaining msg length |
/// | 6           | 2            | Data length         | (Encrypted) req size |
/// | 8           | Data length  | Data                | (Encrypted) request  |
/// | (next)      | Random       | Random              | (Encrypted) random   |
/// | (next)      | 16           | MAC                 | MAC of all above     |
pub fn decrypt_secure_message<C: Crypto>(
    session_id: SessionId,
    keys: &AeadKeys<C>,
    buf: &mut [u8],
    req_size: usize,
) -> SpdmResult<usize> {
    if buf.len() < req_size {
        return Err(ErrorCode::Unspecified);
    }
    let buf = &mut buf[..req_size];
    if req_size < MINIMUM_SECURE_MESSAGE_LENGTH {
        return Err(ErrorCode::InvalidRequest);
    }
    let their_session_id: SessionId = buf[..4].try_into().unwrap();
    if session_id != their_session_id {
        return Err(ErrorCode::InvalidRequest);
    }
    let remaining_size =
        u16::from_le_bytes(buf[LENGTH_OFFSET..LENGTH_OFFSET + 2].try_into().unwrap()) as usize;
    let (header, body) = buf.split_at_mut(CIPHERTEXT_OFFSET);
    if body.len() < remaining_size || remaining_size < 2 + AES_GCM_128_TAG_SIZE {
        return Err(ErrorCode::InvalidRequest);
    }
    let (ciphertext, tag) = body.split_at_mut(body.len() - AES_GCM_128_TAG_SIZE);
    let tag: &AesGcm128Tag = (&*tag).try_into().unwrap();
    C::aes_gcm_decrypt(&keys.key, &keys.iv, header, tag, ciphertext)
        .map_err(|_| ErrorCode::DecryptError)?;
    let plaintext = ciphertext;
    let message_size = u16::from_le_bytes(plaintext[..2].try_into().unwrap()) as usize;
    if plaintext.len() < 2 + message_size {
        return Err(ErrorCode::DecryptError);
    }
    Ok(message_size)
}

/// The message format of a SPDM secure message is:
///
/// | Byte offset | Size (bytes) | Field               | Description          |
/// | :---------- | :----------- | :------------------ | :------------------- |
/// | 0           | 4            | SessionId           |                      |
/// | 4           | 2            | Length              | Remaining msg length |
/// | 6           | 2            | Data length         | (Encrypted) req size |
/// | 8           | Data length  | Data                | (Encrypted) request  |
/// | (next)      | Random       | Random              | (Encrypted) random   |
/// | (next)      | 16           | MAC                 | MAC of all above     |
pub fn encrypt_secure_message<C: Crypto>(
    session_id: SessionId,
    keys: &AeadKeys<C>,
    buf: &mut [u8],
    resp_size: usize,
) -> SpdmResult<usize> {
    let mut random_length = MaybeUninit::<u8>::uninit();
    let mut random_length =
        C::random_bytes(Out::from_out((&mut random_length).into()))?[0] as usize;
    // Scale `random_length` between 1~16.
    random_length &= 0x0F;
    random_length += 1;
    let encrypted_resp_size = REQUEST_OFFSET + resp_size + random_length + AES_GCM_128_TAG_SIZE;
    if buf.len() < encrypted_resp_size {
        return Err(ErrorCode::ResponseTooLarge);
    }
    let random_offset = REQUEST_OFFSET + resp_size;
    C::random_bytes(
        buf[random_offset..random_offset + random_length]
            .manually_drop_mut()
            .into(),
    )?;
    if resp_size > u16::MAX as usize || encrypted_resp_size > u16::MAX as usize {
        return Err(ErrorCode::Unspecified);
    }
    buf[CIPHERTEXT_OFFSET..CIPHERTEXT_OFFSET + 2]
        .copy_from_slice(&(resp_size as u16).to_le_bytes());
    let (header, body) = buf[..encrypted_resp_size].split_at_mut(CIPHERTEXT_OFFSET);
    header[..4].copy_from_slice(&session_id);
    header[LENGTH_OFFSET..LENGTH_OFFSET + 2]
        .copy_from_slice(&((encrypted_resp_size - CIPHERTEXT_OFFSET) as u16).to_le_bytes());
    let (plaintext, tag) = body.split_at_mut(body.len() - AES_GCM_128_TAG_SIZE);
    let tag: &mut AesGcm128Tag = (&mut *tag).try_into().unwrap();
    C::aes_gcm_encrypt(
        &keys.key,
        &keys.iv,
        header,
        plaintext,
        tag.manually_drop_mut().into(),
    )?;
    Ok(encrypted_resp_size)
}
