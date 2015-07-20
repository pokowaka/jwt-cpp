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
#ifndef SRC_JWT_JWT_H_
#define SRC_JWT_JWT_H_

#include <jansson.h>
#include <stddef.h>
#include <exception>
#include <memory>
#include <string>
#include "validators/claims/claimvalidator.h"
#include "validators/messagevalidator.h"


// Stack allocated signature.
#define MAX_SIGNATURE_LENGTH 256

class TokenFormatError : public std::runtime_error {
 public:
  explicit TokenFormatError(std::string msg) : std::runtime_error(msg) { }
};


/**
 * A Json web token. This class can parse and encode a JSON Web JWT (JWT).
 * It folows the spec from http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html
 */
class JWT {
 public:
  ~JWT();

  /**
   * Parses the given string and validates it with the given validators.
   * Note: Omitting the validators will still result in a parsed token.
   *
   * @param jwsToken String containing a valid webtoken
   * @param verifier Optional verifier used to validate the signature.
   * @param validator Optional validator to validate the claims in this token.
   * @return nullptr if string cannot be parsed, otherwise a token.
   */
  static JWT *Decode(std::string jwsToken, MessageValidator *verifier = nullptr,
                     ClaimValidator *validator = nullptr);

  static JWT *Decode(const char *jws_token, size_t num_jws_token,
                     MessageValidator *verifier = nullptr, ClaimValidator *validator = nullptr);

  /**
   * Encodes the given json payload and optional header with the given signer.
   *
   * @param signer The MessageSigner used to sign the resulting token.
   * @param payload The payload for this token.
   * @param header The optional header. Note the "jwt" and "alg" fields will be set
   * @return a char[] with a signed token. To be cleared up with calling delete[]
   */
  static char *Encode(MessageSigner *signer, json_t *payload, json_t *header = nullptr);

  inline const json_t* header() { return header_; }
  inline const json_t* payload() { return payload_; }
  inline bool IsSigned() { return signed_ ; }
  inline bool IsValid() { return valid_; }

 private:
  JWT(json_t* header, json_t* payload, bool signature, bool claim);

  static json_t* ExtractPayload(const char* payload, size_t num_payload);
  static bool VerifySignature(json_t* header_claims_, const char*header,
                                   size_t num_header_and_payload, const char*signature,
                                   size_t num_signature, MessageValidator *verifier);

  json_t* header_;
  json_t* payload_;
  bool signed_;
  bool valid_;
};

typedef std::unique_ptr<JWT> jwt_ptr;
#endif  // SRC_JWT_JWT_H_
