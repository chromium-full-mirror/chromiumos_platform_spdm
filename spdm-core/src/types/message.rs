// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use core::mem::size_of;

use spdm_types::crypto::{
    EcP256UncompressedPoint, EcdsaP256Signature, Sha256Hash, ECDSA_P256_SIGNATURE_SIZE,
    SHA256_HASH_SIZE,
};
use spdm_types::deps::IdentityPublicKey;
use zerocopy::{AsBytes, FromBytes, LayoutVerified, LittleEndian, Unaligned, U16};

use super::code::{Param1, Param2, RequestCode, ResponseCode};
use super::error::ErrorCode;
use super::version::SpdmVersion;

pub const GET_VERSION_REQUEST_SIZE: usize = 4;
pub const VERSION_RESPONSE_SIZE: usize = 8;

pub const GET_PUBLIC_KEY_RESPONSE_SIZE: usize = 4 + IdentityPublicKey::SIZE;
pub const GIVE_PUBLIC_KEY_RESPONSE_SIZE: usize = 4;

// Session ID types: `SessionId` is combined by 2 `HalfSessionId`s, one from
// the requester and one from the responder.
pub type HalfSessionId = [u8; 2];
pub type SessionId = [u8; 4];

pub type SequenceNumber = u64;

macro_rules! try_from_u8_arr {
    ($Request:ty) => {
        impl<'a> TryFrom<&'a [u8]> for &'a $Request {
            type Error = ErrorCode;

            fn try_from(buf: &'a [u8]) -> Result<Self, Self::Error> {
                Ok(
                    LayoutVerified::<&'a [u8], $Request>::new_unaligned_from_prefix(buf)
                        .ok_or(ErrorCode::Unspecified)?
                        .0
                        .into_ref(),
                )
            }
        }
    };
}

macro_rules! try_from_mut_u8_arr {
    ($Response:ty) => {
        impl<'a> TryFrom<&'a mut [u8]> for &'a mut $Response {
            type Error = ErrorCode;

            fn try_from(buf: &'a mut [u8]) -> Result<Self, Self::Error> {
                Ok(
                    LayoutVerified::<&'a mut [u8], $Response>::new_unaligned_from_prefix(buf)
                        .ok_or(ErrorCode::Unspecified)?
                        .0
                        .into_mut(),
                )
            }
        }
    };
}

// GetPubKey related types.

#[repr(C, packed)]
#[derive(FromBytes, AsBytes, Unaligned)]
pub struct GetPubKeyResponse {
    pub version: SpdmVersion,
    pub request_code: RequestCode,
    /// Reserved.
    pub param1: Param1,
    /// Reserved.
    pub param2: Param2,
    /// Responder identity public key.
    pub public_key: IdentityPublicKey,
}
try_from_u8_arr!(GetPubKeyResponse);

// KeyExchange related types.

pub type SessionPolicy = u8;
pub type MutAuthRequested = u8;
pub type SlotIdParam = u8;

#[repr(C, packed)]
#[derive(FromBytes, AsBytes, Unaligned)]
pub struct KeyExchangeRequest {
    pub version: SpdmVersion,
    pub request_code: RequestCode,
    /// Type of measurements requested. Should be 0.
    pub param1: Param1,
    /// SlotID requested. Should be 0xFF.
    pub param2: Param2,
    /// 2-byte half of session ID.
    pub req_session_id: HalfSessionId,
    /// Session policy requested. Should be 0.
    pub session_policy: SessionPolicy,
    pub reserved: u8,
    /// Random data - just to provide entropy to the request, which is used
    /// as part of data to be signed.
    pub random_data: [u8; 32],
    /// Requester ECDHE public key.
    pub exchange_data: EcP256UncompressedPoint,
    /// Used to communicate the secure messaging protocol. We used a fixed protocol
    /// here and request the requester to set the opaque data size as 0 and include
    /// no opaque data.
    pub opaque_data_size: U16<LittleEndian>,
}
try_from_u8_arr!(KeyExchangeRequest);

impl KeyExchangeRequest {
    pub const SIZE: usize = size_of::<Self>();
}

#[repr(C, packed)]
#[derive(FromBytes, AsBytes, Unaligned)]
pub struct KeyExchangeResponse {
    pub version: SpdmVersion,
    pub response_code: ResponseCode,
    /// Heartbeat period. Should be set to 0.
    pub param1: Param1,
    /// Reserved. Should be set to 0.
    pub param2: Param2,
    /// 2-byte half of session ID.
    pub resp_session_id: HalfSessionId,
    /// Should be set to NO_ENCAPSULATE.
    pub mut_auth_requested: MutAuthRequested,
    /// Should be set to PROVISIONED_SLOT_ID.
    pub slot_id_param: SlotIdParam,
    /// Random data - just to provide entropy to the response, which is used
    /// as part of data to be signed.
    pub random_data: [u8; 32],
    /// Responder ECDHE public key.
    pub exchange_data: EcP256UncompressedPoint,
    /// Used to communicate the secure messaging protocol. We used a fixed protocol
    /// here and include no opaque data, so this field should be set to 0.
    pub opaque_data_size: U16<LittleEndian>,
    /// Signature of the transcript hash using the identity key. Refer to the spec
    /// regarding detailed signature algorithm.
    pub signature: EcdsaP256Signature,
    /// HMAC of the transcript hash TH1 using the established session key.
    pub responder_verify_data: Sha256Hash,
}
try_from_u8_arr!(KeyExchangeResponse);
try_from_mut_u8_arr!(KeyExchangeResponse);

impl KeyExchangeResponse {
    pub const SIZE: usize = size_of::<Self>();
    /// The KeyExchangeResponse size without signature and hmac.
    pub const PARTIAL_SIZE: usize = Self::SIZE - ECDSA_P256_SIGNATURE_SIZE - SHA256_HASH_SIZE;
    // Some fixed constants we return in this response.
    pub const NO_HEARTBEAT: Param1 = 0;
    pub const NO_ENCAPSULATE: MutAuthRequested = 1;
    pub const PROVISIONED_SLOT_ID: SlotIdParam = 0xF;
}

#[repr(C, packed)]
#[derive(FromBytes, AsBytes, Unaligned)]
pub struct GivePubKeyRequest {
    pub version: SpdmVersion,
    pub request_code: RequestCode,
    /// Reserved.
    pub param1: Param1,
    /// Reserved.
    pub param2: Param2,
    /// Requester identity public key.
    pub public_key: IdentityPublicKey,
}
try_from_u8_arr!(GivePubKeyRequest);

impl GivePubKeyRequest {
    pub const SIZE: usize = size_of::<Self>();
}

#[repr(C, packed)]
#[derive(FromBytes, AsBytes, Unaligned)]
pub struct FinishRequest {
    pub version: SpdmVersion,
    pub request_code: RequestCode,
    /// Bit 0 indicates whether the signature field is included.
    /// We ignore this field.
    pub param1: Param1,
    /// SlotID. We ignore this field.
    pub param2: Param2,
    /// Signature of the transcript hash using the identity key. Refer to the spec
    /// regarding detailed signature algorithm.
    pub signature: EcdsaP256Signature,
    /// HMAC of the transcript hash using the established session key.
    pub requester_verify_data: Sha256Hash,
}
try_from_u8_arr!(FinishRequest);

impl FinishRequest {
    pub const SIZE: usize = size_of::<Self>();
    /// The FinishRequest size without signature and hmac.
    pub const PARTIAL_SIZE: usize = Self::SIZE - ECDSA_P256_SIGNATURE_SIZE - SHA256_HASH_SIZE;
}
