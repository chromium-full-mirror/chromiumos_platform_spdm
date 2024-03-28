// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements the generic SPDM types and utils used by both
//! requester and responder.

#![cfg_attr(not(test), no_std)]
pub mod session;
pub mod types;
