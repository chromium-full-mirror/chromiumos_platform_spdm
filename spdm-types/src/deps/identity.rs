// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::Crypto;
use crate::crypto::EcP256UncompressedPoint;

/// The identity public key is directly put into the GetPubKey response field
/// without algorithm identifiers, so the format is fixed: a P-256 EC point
/// in uncompressed format.
pub type IdentityPublicKey = EcP256UncompressedPoint;

/// Identity trait defines the interface to access the SPDM identity key pair.
pub trait Identity {
    type Crypto: Crypto;

    /// Gets the reference of the identity public key.
    fn identity_public_key(&self) -> &IdentityPublicKey;
    /// Gets the reference of the identity private key handle.
    fn identity_private_key_handle(&self) -> &<Self::Crypto as Crypto>::IdentityPrivateKeyHandle;
    /// Checks whether |public_key| is a valid identity public key.
    fn is_public_key_valid(public_key: &IdentityPublicKey) -> bool;
}
