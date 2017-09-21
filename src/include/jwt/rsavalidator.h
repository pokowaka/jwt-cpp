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
#ifndef SRC_INCLUDE_JWT_RSAVALIDATOR_H_
#define SRC_INCLUDE_JWT_RSAVALIDATOR_H_

#include "jwt/messagevalidator.h"
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <string>

/**
 * The RSAValidator can sign and validate the RSASSA-PKCX-v1_5 family of
 * signature algorithms.
 */
class RSAValidator : public MessageSigner {
public:
  explicit RSAValidator(std::string algorithm, const EVP_MD *md,
                        const std::string &public_key);
  explicit RSAValidator(std::string algorithm, const EVP_MD *md,
                        const std::string &public_key,
                        const std::string &private_key);
  virtual ~RSAValidator();

  bool Verify(json jsonHeader, const uint8_t *header, size_t num_header,
              const uint8_t *signature, size_t num_signature);
  bool Sign(const uint8_t *header, size_t num_header, uint8_t *signature,
            size_t *num_signature);

  inline std::string algorithm() const { return algorithm_; }
  std::string toJson() const;

private:
  EVP_PKEY *LoadKey(const char *key, bool public_key);

  std::string algorithm_;
  EVP_PKEY *private_key_;
  EVP_PKEY *public_key_;
  const EVP_MD *md_;
};

/**
 * RSASSA-PKCS-v1_5 using SHA-256 hash
 */
class RS256Validator : public RSAValidator {
public:
  explicit RS256Validator(const std::string &public_key)
      : RSAValidator("RS256", EVP_sha256(), public_key) {}
  explicit RS256Validator(const std::string &public_key,
                          const std::string &private_key)
      : RSAValidator("RS256", EVP_sha256(), public_key, private_key) {}
};

/**
 * RSASSA-PKCS-v1_5 using SHA-384 hash
 */
class RS384Validator : public RSAValidator {
public:
  explicit RS384Validator(const std::string &public_key)
      : RSAValidator("RS384", EVP_sha384(), public_key) {}
  explicit RS384Validator(const std::string &public_key,
                          const std::string &private_key)
      : RSAValidator("RS384", EVP_sha384(), public_key, private_key) {}
};

/**
 * RSASSA-PKCS-v1_5 using SHA-512 hash
 */
class RS512Validator : public RSAValidator {
public:
  explicit RS512Validator(const std::string &public_key)
      : RSAValidator("RS512", EVP_sha512(), public_key) {}
  explicit RS512Validator(const std::string &public_key,
                          const std::string &private_key)
      : RSAValidator("RS512", EVP_sha512(), public_key, private_key) {}
};
#endif // SRC_INCLUDE_JWT_RSAVALIDATOR_H_
