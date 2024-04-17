// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Stub dependencies used in tests.

#![cfg_attr(not(test), no_std)]
mod crypto;
mod dispatch;
mod identity;
mod vendor;

pub use crypto::*;
pub use dispatch::*;
pub use identity::*;
pub use vendor::*;
