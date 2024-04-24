// Copyright 2024 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use proc_macro::*;

/// Specify the attribute you want compile in for host-only builds
#[proc_macro_attribute]
pub fn cfg_host_attr(attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut stream: TokenStream = format!(r#"#[cfg_attr(target_os = "linux", {attr})]"#)
        .parse()
        .expect("invalid specified attribute");
    stream.extend(item);
    stream
}

/// Use to compile in item host-only builds
#[proc_macro_attribute]
pub fn cfg_host(_: TokenStream, item: TokenStream) -> TokenStream {
    let mut stream: TokenStream = r#"#[cfg(target_os = "linux")]"#.to_string().parse().unwrap();
    stream.extend(item);
    stream
}

/// Specify the mockable attribute for test-only builds with mock feature enabled
#[proc_macro_attribute]
pub fn cfg_test_mockable(_: TokenStream, item: TokenStream) -> TokenStream {
    let mut stream: TokenStream = r#"#[cfg_attr(all(test, feature = "mock"), mockable)]"#
        .parse()
        .unwrap();
    stream.extend(item);
    stream
}

/// Use to compile in item test-only builds with mock feature enabled
#[proc_macro_attribute]
pub fn cfg_test_mock(_: TokenStream, item: TokenStream) -> TokenStream {
    let mut stream: TokenStream =
        r#"#[cfg(all(test, feature = "mock"))]"#.to_string().parse().unwrap();
    stream.extend(item);
    stream
}
