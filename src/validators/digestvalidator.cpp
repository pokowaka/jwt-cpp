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
#include "validators/digestvalidator.h"
#include <string.h>
#include <string>
#include <memory>

DigestValidator::DigestValidator(const char *algorithm,
    const EVP_MD *md, const std::string &key) {
  key_size_ = md->md_size;
  algorithm_ = algorithm;
  HMAC_CTX_init(&ctx_);
  HMAC_Init_ex(&ctx_, key.c_str(), key.size(), md, NULL);
}

DigestValidator::~DigestValidator() {
  HMAC_CTX_cleanup(&ctx_);
}

bool DigestValidator::VerifySignature(const uint8_t *header, size_t num_header,
                                      const uint8_t *signature, size_t num_signature) {
  // No need to calc the signature if it is going be the wrong size.
  if (num_signature != key_size_ || signature == nullptr)
    return false;

  // We could probably hold this on the stack..
  size_t num_local_signature = key_size_;
  std::unique_ptr<uint8_t[]> local_signature(new uint8_t[key_size_]);
  return Sign(header, num_header, local_signature.get(), &num_local_signature)
    && num_local_signature == key_size_
    && const_time_cmp(local_signature.get(), signature, key_size_) == 0;
}

int DigestValidator::const_time_cmp(const void *a, const void *b, const size_t size) {
  const unsigned char *_a = (const unsigned char *) a;
  const unsigned char *_b = (const unsigned char *) b;
  unsigned char result = 0;
  size_t i;

  for (i = 0; i < size; i++) {
    result |= _a[i] ^ _b[i];
  }

  return result; /* returns 0 if equal, nonzero otherwise */
}

bool DigestValidator::Sign(const uint8_t *header, size_t num_header,
                           uint8_t *signature, size_t *num_signature) {
  if (signature == NULL || *num_signature < key_size_) {
      *num_signature = key_size_;
      return false;
  }
  HMAC_Init(&ctx_, 0, 0, 0);  // We need to clean out any state..
  return HMAC_Update(&ctx_, header, num_header) && HMAC_Final(&ctx_, signature, (unsigned int*) num_signature);
}
