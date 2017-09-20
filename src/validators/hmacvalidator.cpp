// Copyright (c) 2015 Erwin Jansen
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#include "jwt/hmacvalidator.h"
#include <string.h>
#include <memory>
#include <sstream>
#include <string>

HMACValidator::HMACValidator(const char *algorithm,
    const EVP_MD *md, const std::string &key) :
  md_(md), algorithm_(algorithm), key_size_(EVP_MD_size(md)), key_(key) {
}

HMACValidator::~HMACValidator() {
}

bool HMACValidator::Verify(json_t *jsonHeader, const uint8_t *header, size_t num_header,
                           const uint8_t *signature, size_t num_signature) {
  // No need to calc the signature if it is going be the wrong size.
  if (num_signature != key_size_ || signature == nullptr)
    return false;

  size_t num_local_signature = MAX_HMAC_KEYLENGTH;
  uint8_t local_signature[MAX_HMAC_KEYLENGTH];
  return Sign(header, num_header, local_signature, &num_local_signature)
    && num_local_signature == key_size_
    && const_time_cmp(local_signature, signature, key_size_) == 0;
}

int HMACValidator::const_time_cmp(const uint8_t *a, const uint8_t *b, const size_t size) {
  uint8_t result = 0;
  size_t i;

  for (i = 0; i < size; i++) {
    result |= a[i] ^ b[i];
  }

  return result; /* returns 0 if equal, nonzero otherwise */
}

bool HMACValidator::Sign(const uint8_t *header, size_t num_header,
                           uint8_t *signature, size_t *num_signature) {
  if (signature == NULL || *num_signature < key_size_) {
      *num_signature = key_size_;
      return false;
  }
  HMAC_CTX* ctx = HMAC_CTX_new();
  HMAC_Init_ex(ctx, key_.c_str(), key_.size(), md_, NULL);
  bool sign = HMAC_Update(ctx, header, num_header) &&
    HMAC_Final(ctx, signature, (unsigned int*) num_signature);
  HMAC_CTX_free(ctx);
  return sign;
}


std::string HMACValidator::toJson() const {
  std::ostringstream msg;
  msg << "{ \"" << algorithm() << "\" : { \"secret\" : \"" << key_ << "\" } }";
  return msg.str();
}
