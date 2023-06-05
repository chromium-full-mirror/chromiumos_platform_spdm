// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "spdm.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MAX_SPDM_RESPONSE_SIZE 1024
#define SPDM_THIS_VERSION 0x13
#define SPDM_CODE_ERROR 0x7F
#define SPDM_ERR_UNSPECIFIED 0x05

#define UNSPECIFIED_ERROR_RESPONSE_SIZE 4

const uint8_t UNSPECIFIED_ERROR_RESPONSE[UNSPECIFIED_ERROR_RESPONSE_SIZE] = {
    SPDM_THIS_VERSION, SPDM_CODE_ERROR, SPDM_ERR_UNSPECIFIED, 0};

int main() {
  uint8_t buf[MAX_SPDM_RESPONSE_SIZE] = {};
  size_t resp_size = MAX_SPDM_RESPONSE_SIZE;
  dispatch_spdm_request(0, buf, 0, &resp_size);
  if (resp_size < UNSPECIFIED_ERROR_RESPONSE_SIZE) {
    printf("Response size too small!\n");
    return 1;
  }
  if (memcmp(buf, UNSPECIFIED_ERROR_RESPONSE,
             UNSPECIFIED_ERROR_RESPONSE_SIZE)) {
    printf("Unexpected response!\n");
    return 1;
  }
  printf("Test success!\n");
  return 0;
}
