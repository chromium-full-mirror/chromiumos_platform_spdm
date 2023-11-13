// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Specifies the trait dependencies SPDM needs. Each user of the library
//! needs to define concret instances of the SPDM dependency traits.

mod crypto;
mod identity;
mod vendor;

pub use crypto::*;
pub use identity::*;
pub use vendor::*;

/// `SpdmDeps` defines the trait dependencies of `Spdm` so it only needs
/// to be generic on a single type with `SpdmDeps` trait bound.
pub trait SpdmDeps {
    type Crypto: Crypto;
    type Identity: Identity<Crypto = Self::Crypto>;
    type Vendor: Vendor;
}
