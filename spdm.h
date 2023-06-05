// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SPDM_SPDM_H
#define SPDM_SPDM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Dispatches the SPDM request to the global SPDM responder state machine.
// `is_secure` should be set to whether the request is secured (clear message
// if not).
// `buf` should contain the SPDM request and the SPDM response will be written
// back to `buf`.
// `req_size` should contain the size in bytes of the SPDM request.
// `resp_size` should contain the maximum size in bytes we can write to `buf`,
// and will be set to the response size.
extern void dispatch_spdm_request(bool is_secure, uint8_t *buf, size_t req_size,
                                  size_t *resp_size);

#ifdef __cplusplus
}
#endif

#endif /* SPDM_SPDM_H */
