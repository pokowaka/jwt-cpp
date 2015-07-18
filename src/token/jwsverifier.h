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
#ifndef SRC_TOKEN_JWSVERIFIER_H_
#define SRC_TOKEN_JWSVERIFIER_H_


#include <string.h>
#include <openssl/hmac.h>
#include <map>
#include <string>
#include "validators/messagevalidator.h"

// We try to stack allocate for the hmac..
// HS256  32
// HS384  48
// HS512  64
#define MAX_SIGNATURE_LENGTH 1024
/**
 * A JwsVerifier keeps track of a set of message validators that
 * can be used to validate if the given header is properly signed.
 */
class JwsVerifier {
 public:
  JwsVerifier() {}
  JwsVerifier(MessageValidator **validators, size_t num_validators);
  explicit JwsVerifier(MessageValidator* validator);

  /**
   * Verfies the given jose header and signature. Uses the verifier defined
   * by algorithm parameter.
   *
   * @params algorithm The algorithm used to validate the header
   * @param header The header to be validated
   * @param num_header The length of the header
   * @param signature The base64 encoded signature
   * @param num_signature The length of the base64 encoded signature
   * @return true if the signature is valid, false otherwise.
   */
  bool VerifySignature(std::string algorithm, const char *header, size_t num_header,
      const char *signature, size_t num_signature) const;
  /**
   * Signs the header using the given algorithm. If the signature buffer is to small
   * or null the needed size will be set in *num_signature. The signature will contain
   * a null terminated base64 encoded string.
   *
   * @param header The header to be signed
   * @param num_header the number chars in the header
   * @param signature The char array to receiver the signature
   * @param num_signature The size of the signature array.
   * @return pointer to signature array.
   */
  char* Sign(std::string algorithm, const char *header, size_t num_header,
      char *signature, size_t *num_signature) const;

  /**
   * Registers the given validator.
   */
  bool RegisterValidator(MessageValidator *validator);

 private:
  std::map<std::string, MessageValidator *> validator_map_;
};
#endif  // SRC_TOKEN_JWSVERIFIER_H_
