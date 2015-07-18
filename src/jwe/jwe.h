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

#ifndef SRC_JWE_JWE_H_
#define SRC_JWE_JWE_H_


#include <jansson.h>
#include <openssl/evp.h>

// The size of the IV property must be the same as the BlockSize
// property divided by 8.
// So in our case this should work just fine
#define MAX_IV_SIZE 128

/**
 * Allows you to decrypt tokens with
 * alg: 'RSA1_5' and enc: 'A256CBC'
 *
 * TODO: This really needs to be extended.
 */
class Jwe {
 public:
  explicit Jwe(const char* private_key);
  ~Jwe();

  bool Decrypt(json_t* jwe_header, uint8_t *payload, size_t num_payload,
      uint8_t *signature, size_t num_signature,
      uint8_t **decrypted, size_t *num_decrypted) const;

 private:
  inline static bool isSet(json_t *json, const char *key, const char *expected);
  static RSA *createRSA(const char *key, bool public_key);
  RSA* rsa_;
};


#endif  // SRC_JWE_JWE_H_
