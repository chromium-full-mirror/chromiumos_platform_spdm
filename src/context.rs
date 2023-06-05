// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use spdm_core::SpdmContext;

/// Implements SpdmContext by interacting with the static eal functions.
#[repr(C, packed)]
pub struct EalSpdmContext;

impl SpdmContext for EalSpdmContext {}
