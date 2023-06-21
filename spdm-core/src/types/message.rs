// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::deps::IdentityPublicKey;

pub const GET_VERSION_REQUEST_SIZE: usize = 4;
pub const VERSION_RESPONSE_SIZE: usize = 8;

pub const GET_PUBLIC_KEY_RESPONSE_SIZE: usize = 4 + IdentityPublicKey::SIZE;
