// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use open_enum::open_enum;
use spdm_proc_macros::cfg_host_attr;
use zerocopy::{AsBytes, FromBytes};

#[repr(u8)]
#[open_enum]
#[cfg_host_attr(derive(Debug))]
#[derive(Copy, Clone, FromBytes, AsBytes)]
pub enum RequestCode {
    GetVersion = 0x84,
    KeyExchange = 0xE4,
    Finish = 0xE5,
    // We use reserved request codes as the Get/GivePubKey request codes because
    // we don't want to parse them as vendor commands.
    GetPubKey = 0xF0,
    GivePubKey = 0xF1,
    VendorCommand = 0xF2,
}

#[repr(u8)]
#[open_enum]
#[cfg_host_attr(derive(Debug))]
#[derive(Clone, Copy, FromBytes, AsBytes)]
pub enum ResponseCode {
    Version = 0x04,
    KeyExchange = 0x64,
    Finish = 0x65,
    Error = 0x7F,
    // We use reserved response codes as the Get/GivePubKey response code because
    // we don't want to parse them as vendor commands.
    GetPubKey = 0x10,
    GivePubKey = 0x11,
    VendorCommand = 0x12,
}

// `Param1` and `Param2` are 1-byte params that appear in most SPDM message formats
// as the 3rd and 4th bytes.
pub type Param1 = u8;
pub type Param2 = u8;
