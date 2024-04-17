// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Currently there is no need for error handling based on different kinds of
// error returned by the SPDM requester, so just use an empty struct.
#[derive(Debug, PartialEq, Eq)]
pub struct RequesterError;
pub type RequesterResult<T> = Result<T, RequesterError>;
pub type RequesterStatus = RequesterResult<()>;
