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
#ifndef SRC_INCLUDE_JWT_JWT_H_
#define SRC_INCLUDE_JWT_JWT_H_

#include "jwt/claimvalidator.h"
#include "jwt/json.hpp"
#include "jwt/messagevalidator.h"
#include <memory>
#include <stddef.h>
#include <string>
#include <utility>

// Stack allocated signature.
#define MAX_SIGNATURE_LENGTH 256

/**
 * JSON Web Token (JWT) is a compact, URL-safe means of representing claims to
 * be transferred between two parties. The claims in a JWT are encoded as a JSON
 * object that is used as the payload of a JSON Web Signature (JWS) structure or
 * as the plaintext of a JSON Web Encryption (JWE) structure, enabling the
 * claims to be digitally signed or integrity protected with a Message
 * Authentication Code (MAC) and/or encrypted.
 *
 * This class can parse, validate and encode anf sign such tokens.
 * See the
 * [spec](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html) for
 * more details.
 */
class JWT {
  using json = nlohmann::json;

public:
  ~JWT();

  /**
   * Parses an encoded web token and validates it.
   *
   * @param jwsToken String containing a valid webtoken
   * @param verifier Optional verifier used to validate the signature. If this
   *                 parameter is null the signature will not be verified.
   * @param validator Optional validator to validate the claims in this token.
   * The payload will not be validated if this parameter is null
   * @throw TokenFormatError in case the token cannot be parsed
   * @throw InvalidSignatureError in case the token is not signed
   * @throw InvalidClaimError in case the payload cannot be validated
   */
  static JWT *Decode(std::string jwsToken, MessageValidator *verifier = nullptr,
                     ClaimValidator *validator = nullptr);

  /**
   * Decodes and validates a JSON Web Token.
   *
   * @param jws_token String containing a valid webtoken
   * @param num_jws_token The number of bytes in the jws_token string
   * @param verifier Optional verifier used to validate the JOSE header. No
   *                 verification will be done if this parameter is null .
   * @param validator Optional validator to validate the claims in this token.
   * The payload will not be validated if this parameter is null
   * @throw TokenFormatError in case the token cannot be parsed
   * @throw InvalidSignatureError in case the token is not signed
   * @throw InvalidClaimError in case the payload cannot be validated
   */
  static JWT *Decode(const char *jws_token, size_t num_jws_token,
                     MessageValidator *verifier = nullptr,
                     ClaimValidator *validator = nullptr);

  /**
   * Encodes the given json payload and optional header with the given signer.
   *
   * @param signer The MessageSigner used to sign the resulting token.
   * @param payload The payload for this token.
   * @param header The optional header. Note the "jwt" and "alg" fields will be
   * set
   * @return a char[] with a signed token. To be cleared up with calling
   * delete[]
   */
  static std::string Encode(MessageSigner *signer, json payload,
                            json header = nullptr);

  /**
   * The contents of the JOSE Header describe the cryptographic operations
   * applied to the JWT Claims Set.  Callers do not own the reference returned
   * and should not free it.
   */
  inline const json header() { return header_; }

  /**
   * A JSON object that contains the claims conveyed by the JWT.  Callers do not
   * own the reference returned and should not free it.
   */
  inline const json payload() { return payload_; }

private:
  JWT(json header, json payload);

  static json ExtractPayload(const char *payload, size_t num_payload);
  static bool VerifySignature(json header_claims_, const char *header,
                              size_t num_header_and_payload,
                              const char *signature, size_t num_signature,
                              MessageValidator *verifier);

  json header_;
  json payload_;
};

/** Auto pointer that will release the token when it goes out of scope */
typedef std::unique_ptr<JWT> jwt_ptr;
#endif // SRC_INCLUDE_JWT_JWT_H_
