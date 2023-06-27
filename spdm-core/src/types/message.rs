// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::deps::IdentityPublicKey;

pub const GET_VERSION_REQUEST_SIZE: usize = 4;
pub const VERSION_RESPONSE_SIZE: usize = 8;

pub const GET_PUBLIC_KEY_RESPONSE_SIZE: usize = 4 + IdentityPublicKey::SIZE;

// Session ID types: `SessionId` is combined by 2 `HalfSessionId`s, one from
// the requester and one from the responder.
pub type HalfSessionId = [u8; 2];
pub type SessionId = [u8; 4];
