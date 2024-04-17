// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use spdm::types::version::SpdmVersion;

pub const SPDM_THIS_VERSION: SpdmVersion = 0x13;
/// The current SPDM implementation version. If we fix bugs or make any
/// requester-visible changes, the requester needs to be able to distinguish
/// the implementation version. We don't want to increment SPDM_THIS_VERSION
/// in that case because we want to keep it consistent with the spec version
/// we're following.
pub const SPDM_THIS_ALPHA_VERSION: SpdmVersion = 0x00;
