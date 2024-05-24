// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::mem::{self, MaybeUninit};

use spdm_types::crypto::{
    AesGcm128Iv, Sha256Hash, AES_GCM_128_IV_SIZE, AES_GCM_128_KEY_SIZE, SHA256_HASH_SIZE,
};
use spdm_types::deps::Crypto;
use uninit::prelude::*;

use super::{SequenceNumbers, Session, SessionPhase, SpdmRole};
use crate::types::error::{ErrorCode, SpdmResult, SpdmStatus};
use crate::types::message::SequenceNumber;

const MAX_BIN_CONCAT_SIZE: usize = /* Longest prefix length */ 22 + 32;

const BIN_STR_VERSION: &str = "spdm1.3 ";
const BIN_STR0_LABEL: &str = "derived";
const BIN_STR1_LABEL: &str = "req hs data";
const BIN_STR2_LABEL: &str = "rsp hs data";
const BIN_STR3_LABEL: &str = "req app data";
const BIN_STR4_LABEL: &str = "rsp app data";
const BIN_STR5_LABEL: &str = "key";
const BIN_STR6_LABEL: &str = "iv";
const BIN_STR7_LABEL: &str = "finished";

/// BinConcatBuffer handles different sizes of the `bin_str[x]` strings defined
/// in the spec using a fixed-sized buffer. The difference in size of each string
/// isn't big so this is fine.
struct BinConcatBuffer {
    buf: [MaybeUninit<u8>; MAX_BIN_CONCAT_SIZE],
    size: usize,
}

impl Default for BinConcatBuffer {
    fn default() -> Self {
        Self {
            buf: uninit_array![u8; MAX_BIN_CONCAT_SIZE],
            size: 0,
        }
    }
}

impl BinConcatBuffer {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: The first `self.size` bytes are initialized.
        unsafe { mem::transmute(&self.buf[..self.size]) }
    }

    fn concat(&mut self, data: &[u8]) -> SpdmStatus {
        if self.size + data.len() > MAX_BIN_CONCAT_SIZE {
            return Err(ErrorCode::Unspecified);
        }
        self.buf[self.size..self.size + data.len()]
            .as_out()
            .copy_from_slice(data);
        self.size += data.len();
        Ok(())
    }
}

/// BinConcat string is the concat of:
/// - Length: Size of the hash in 2-byte small-endian representation.
/// - Version: The 8-byte version string ("spdm1.3 " here).
/// - Label: Variable sized label.
/// - Context: `Length` size hash, optional.
fn gen_bin_str(
    length: usize,
    context: Option<&Sha256Hash>,
    label: &str,
    buf: &mut BinConcatBuffer,
) -> SpdmStatus {
    buf.concat(&(length as u16).to_le_bytes())?;
    buf.concat(BIN_STR_VERSION.as_bytes())?;
    buf.concat(label.as_bytes())?;
    if let Some(ctx) = context {
        buf.concat(ctx)?;
    }
    Ok(())
}

fn gen_bin_str0(buf: &mut BinConcatBuffer) -> SpdmStatus {
    gen_bin_str(SHA256_HASH_SIZE, None, BIN_STR0_LABEL, buf)
}

fn gen_bin_str1(context: &Sha256Hash, buf: &mut BinConcatBuffer) -> SpdmStatus {
    gen_bin_str(SHA256_HASH_SIZE, Some(context), BIN_STR1_LABEL, buf)
}

fn gen_bin_str2(context: &Sha256Hash, buf: &mut BinConcatBuffer) -> SpdmStatus {
    gen_bin_str(SHA256_HASH_SIZE, Some(context), BIN_STR2_LABEL, buf)
}

fn gen_bin_str3(context: &Sha256Hash, buf: &mut BinConcatBuffer) -> SpdmStatus {
    gen_bin_str(SHA256_HASH_SIZE, Some(context), BIN_STR3_LABEL, buf)
}

fn gen_bin_str4(context: &Sha256Hash, buf: &mut BinConcatBuffer) -> SpdmStatus {
    gen_bin_str(SHA256_HASH_SIZE, Some(context), BIN_STR4_LABEL, buf)
}

fn gen_bin_str5(buf: &mut BinConcatBuffer) -> SpdmStatus {
    gen_bin_str(AES_GCM_128_KEY_SIZE, None, BIN_STR5_LABEL, buf)
}

fn gen_bin_str6(buf: &mut BinConcatBuffer) -> SpdmStatus {
    gen_bin_str(AES_GCM_128_IV_SIZE, None, BIN_STR6_LABEL, buf)
}

fn gen_bin_str7(buf: &mut BinConcatBuffer) -> SpdmStatus {
    gen_bin_str(SHA256_HASH_SIZE, None, BIN_STR7_LABEL, buf)
}

// SAFETY: `main_secret` is guaranteed to be initialized if `Ok` is returned.
pub fn generate_main_secret<'a, C: Crypto>(
    handshake_secret: &C::HmacDerivationKeyHandle,
    main_secret: Out<'a, C::HmacDerivationKeyHandle>,
) -> SpdmResult<&'a mut C::HmacDerivationKeyHandle> {
    const ALL_0: [u8; SHA256_HASH_SIZE] = [0; SHA256_HASH_SIZE];
    let mut bin_str = BinConcatBuffer::default();
    gen_bin_str0(&mut bin_str)?;

    let mut salt1: MaybeUninit<<C as Crypto>::HmacDerivationKeyHandle> =
        MaybeUninit::<C::HmacDerivationKeyHandle>::uninit();
    C::hmac_expand_derivation_key(handshake_secret, bin_str.as_ref(), salt1.as_out())?;
    // SAFETY: `salt1` is guaranteed to be initialized after a successful
    // `hmac_expand_derivation_key`.
    let salt = unsafe { salt1.assume_init() };
    Ok(C::hmac_extract(&salt, &ALL_0, main_secret)?)
}

pub struct MessageSecrets<C: Crypto> {
    request_direction: C::HmacDerivationKeyHandle,
    response_direction: C::HmacDerivationKeyHandle,
}

impl<C: Crypto> MessageSecrets<C> {
    fn split_fields_out(
        out: Out<MessageSecrets<C>>,
    ) -> (
        Out<C::HmacDerivationKeyHandle>,
        Out<C::HmacDerivationKeyHandle>,
    ) {
        // SAFETY: The `secret` variable is only used to cast mutable references
        // of individual fields back to `Out`.
        let secrets = unsafe { out.assume_init() };
        (
            secrets.request_direction.manually_drop_mut().into(),
            secrets.response_direction.manually_drop_mut().into(),
        )
    }
}

// SAFETY: `message_secrets` is guaranteed to be initialized if `Ok` is returned.
pub fn generate_message_secrets<'a, C: Crypto>(
    session: &Session<C>,
    phase: SessionPhase,
    mut message_secrets: Out<'a, MessageSecrets<C>>,
) -> SpdmResult<&'a mut MessageSecrets<C>> {
    let mut req_bin_str = BinConcatBuffer::default();
    let mut rsp_bin_str = BinConcatBuffer::default();
    let secret = match phase {
        SessionPhase::None => return Err(ErrorCode::Unspecified),
        SessionPhase::Handshake => {
            let th = session.th1.as_ref().ok_or(ErrorCode::Unspecified)?;
            gen_bin_str1(th, &mut req_bin_str)?;
            gen_bin_str2(th, &mut rsp_bin_str)?;
            session
                .handshake_secret
                .as_ref()
                .ok_or(ErrorCode::Unspecified)?
        }
        SessionPhase::Data => {
            let th = session.th2.as_ref().ok_or(ErrorCode::Unspecified)?;
            gen_bin_str3(th, &mut req_bin_str)?;
            gen_bin_str4(th, &mut rsp_bin_str)?;
            session.main_secret.as_ref().ok_or(ErrorCode::Unspecified)?
        }
    };
    let (request_direction, response_direction) =
        MessageSecrets::split_fields_out(message_secrets.r());
    C::hmac_expand_derivation_key(secret, req_bin_str.as_ref(), request_direction)?;
    C::hmac_expand_derivation_key(secret, rsp_bin_str.as_ref(), response_direction)?;
    // SAFETY: both fields are guaranteed to be initialized after successful
    // `hmac_expand`s.
    Ok(unsafe { message_secrets.assume_init() })
}

// SAFETY: `finished_key` is guaranteed to be initialized if `Ok` is returned.
pub fn generate_finished_key<'a, C: Crypto>(
    role: SpdmRole,
    message_secrets: &MessageSecrets<C>,
    finished_key: Out<'a, C::HmacSecretKeyHandle>,
) -> SpdmResult<&'a mut C::HmacSecretKeyHandle> {
    let secret = match role {
        SpdmRole::Requester => &message_secrets.request_direction,
        SpdmRole::Responder => &message_secrets.response_direction,
    };
    let mut bin_str = BinConcatBuffer::default();
    gen_bin_str7(&mut bin_str)?;
    Ok(C::hmac_expand_hmac_secret_key(
        secret,
        bin_str.as_ref(),
        finished_key,
    )?)
}

pub struct AeadKeys<C: Crypto> {
    pub key: C::AesGcmKeyHandle,
    pub iv: AesGcm128Iv,
}

impl<C: Crypto> AeadKeys<C> {
    fn split_fields_out(out: Out<AeadKeys<C>>) -> (Out<C::AesGcmKeyHandle>, Out<AesGcm128Iv>) {
        // SAFETY: The `keys` variable is only used to cast mutable references
        // of individual fields back to `Out`.
        let keys = unsafe { out.assume_init() };
        (
            keys.key.manually_drop_mut().into(),
            keys.iv.manually_drop_mut().into(),
        )
    }
}

pub struct AeadSessionKeys<C: Crypto> {
    pub request_keys: AeadKeys<C>,
    pub response_keys: AeadKeys<C>,
}

impl<C: Crypto> AeadSessionKeys<C> {
    fn split_fields_out(out: Out<AeadSessionKeys<C>>) -> (Out<AeadKeys<C>>, Out<AeadKeys<C>>) {
        // SAFETY: The `keys` variable is only used to cast mutable references
        // of individual fields back to `Out`.
        let keys = unsafe { out.assume_init() };
        (
            keys.request_keys.manually_drop_mut().into(),
            keys.response_keys.manually_drop_mut().into(),
        )
    }
}

// SAFETY: `keys` is guaranteed to be initialized if `Ok` is returned.
pub fn generate_directional_keys<'a, C: Crypto>(
    secret: &C::HmacDerivationKeyHandle,
    mut keys: Out<'a, AeadKeys<C>>,
) -> SpdmResult<&'a mut AeadKeys<C>> {
    let mut key_bin_str = BinConcatBuffer::default();
    let mut iv_bin_str = BinConcatBuffer::default();
    gen_bin_str5(&mut key_bin_str)?;
    gen_bin_str6(&mut iv_bin_str)?;
    let (key, iv) = AeadKeys::split_fields_out(keys.r());
    C::hmac_expand_aes_gcm_key(secret, key_bin_str.as_ref(), key)?;
    C::hmac_expand_aes_gcm_iv(secret, iv_bin_str.as_ref(), iv)?;
    // SAFETY: both fields are guaranteed to be initialized after successful
    // `hmac_expand_*`s.
    Ok(unsafe { keys.assume_init() })
}

fn xor_suffix(iv: &mut AesGcm128Iv, seq_num: SequenceNumber) {
    let seq_num_bytes = seq_num.to_be_bytes();
    for i in 4..12 {
        iv[i] ^= seq_num_bytes[i - 4];
    }
}

// SAFETY: `aead_keys` is guaranteed to be initialized if `Ok` is returned.
pub fn generate_aead_keys<'a, C: Crypto>(
    message_secrets: &MessageSecrets<C>,
    sequence_numbers: &SequenceNumbers,
    mut aead_keys: Out<'a, AeadSessionKeys<C>>,
) -> SpdmResult<&'a mut AeadSessionKeys<C>> {
    let (request_keys, response_keys) = AeadSessionKeys::split_fields_out(aead_keys.r());
    let request_keys = generate_directional_keys(&message_secrets.request_direction, request_keys)?;
    let response_keys =
        generate_directional_keys(&message_secrets.response_direction, response_keys)?;
    xor_suffix(&mut request_keys.iv, sequence_numbers.request);
    xor_suffix(&mut response_keys.iv, sequence_numbers.response);
    // SAFETY: both fields are guaranteed to be initialized after successful
    // `generate_directional_keys`s.
    Ok(unsafe { aead_keys.assume_init() })
}

// SAFETY: `keys` is guaranteed to be initialized if `Ok` is returned.
pub fn get_session_keys<'a, C: Crypto>(
    session: &Session<C>,
    phase: SessionPhase,
    keys: &'a mut MaybeUninit<AeadSessionKeys<C>>,
) -> SpdmResult<&'a mut AeadSessionKeys<C>> {
    let mut message_secrets = MaybeUninit::<MessageSecrets<C>>::uninit();
    generate_message_secrets(session, phase, (&mut message_secrets).into())?;
    // SAFETY: `message_secrets` is guaranteed to be initialized after a successful
    // `generate_message_secrets`.
    let message_secrets = unsafe { message_secrets.assume_init() };
    generate_aead_keys(&message_secrets, &session.sequence_numbers, keys.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bin_concat() {
        let mut bin_str = BinConcatBuffer::default();
        assert!(bin_str.concat("hello".as_bytes()).is_ok());
        assert!(bin_str.concat("123".as_bytes()).is_ok());
        assert_eq!(bin_str.as_ref(), "hello123".as_bytes());
    }

    #[test]
    fn test_xor_suffix() {
        let mut iv = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let seq_num = 18446744073709551615; // (1 << 64) - 1
        xor_suffix(&mut iv, seq_num);
        assert_eq!(iv, [1, 2, 3, 4, 250, 249, 248, 247, 246, 245, 244, 243])
    }
}
