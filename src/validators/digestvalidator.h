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
#ifndef SRC_VALIDATORS_DIGESTVALIDATOR_H_
#define SRC_VALIDATORS_DIGESTVALIDATOR_H_

#include <openssl/hmac.h>
#include <string>
#include "validators/messagevalidator.h"

// Maximum length of a signature
// Note that SHA512 is 64 bytes.
#define MAX_KEYLENGTH 64
/**
 * Can sign & validate using an openssl digest function. Signing and Verification
 * are not thread safe functions.
 */
class DigestValidator : public MessageValidator {
 public:
  explicit DigestValidator(const char *algorithm, const EVP_MD *md, const std::string &key);
  virtual ~DigestValidator();

  bool VerifySignature(const uint8_t *header, size_t num_header,
                       const uint8_t *signature, size_t num_signature);
  bool Sign(const uint8_t *header, size_t num_header,
            uint8_t *signature, size_t *num_signature);

  inline unsigned int key_size() const { return key_size_; }
  inline const char *algorithm() const { return algorithm_; }

 private:
  DigestValidator(const DigestValidator&);
  DigestValidator& operator=(const DigestValidator&);

  static int const_time_cmp(const void* a, const void* b, const size_t size);
  HMAC_CTX ctx_;
  unsigned int key_size_;
  const char *algorithm_;
};

class HS256Validator : public DigestValidator {
 public:
  explicit HS256Validator(const std::string &key) : DigestValidator("HS256", EVP_sha256(), key) { }
};

class HS384Validator : public DigestValidator {
 public:
  explicit HS384Validator(const std::string &key) : DigestValidator("HS384", EVP_sha384(), key) { }
};

class HS512Validator : public DigestValidator {
 public:
  explicit HS512Validator(const std::string &key) : DigestValidator("HS512", EVP_sha512(), key) { }
};
#endif  // SRC_VALIDATORS_DIGESTVALIDATOR_H_
