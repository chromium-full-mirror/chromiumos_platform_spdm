// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Specifies the trait dependencies SPDM needs. Each user of the library
//! needs to define concret instances of the SPDM dependency traits.

mod crypto;
mod dispatch;
mod identity;
mod vendor;

pub use crypto::*;
pub use dispatch::*;
pub use identity::*;
pub use vendor::*;
