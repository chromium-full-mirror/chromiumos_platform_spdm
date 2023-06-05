// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Defines the SPDM context trait that specifies the context methods that
//! would be accessed in the SPDM lib.

/// SpdmContext specifies the context methods that would be accessed in the
/// SPDM lib. Each host using this library should implement a concrete context
/// type implementing this trait.
pub trait SpdmContext {}
