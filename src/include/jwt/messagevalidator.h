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
#ifndef SRC_INCLUDE_JWT_MESSAGEVALIDATOR_H_
#define SRC_INCLUDE_JWT_MESSAGEVALIDATOR_H_

#include "jwt/allocators.h"
#include "jwt/json.hpp"
#include "jwt/jwt_error.h"
#include <stdint.h>
#include <string.h>
#include <string>

using json = nlohmann::json;

/**
 * A MessageValidator can verify that a message is properly signed.
 */
class MessageValidator {
public:
  virtual ~MessageValidator() {}

  /**
   * Verifies that the given signature belongs with the given header.
   *
   * @param jsonHeader The parsed jose header
   * @param header the urlbase64 encoded JOSEHeader
   * @param num_header Number of bytes in the header
   * @param signature The binary signature. (Note base64 encoded).
   * @param num_signature The length of the signature.
   */
  virtual bool Verify(json jsonHeader, const uint8_t *header, size_t num_header,
                      const uint8_t *signature, size_t num_signature) = 0;
  virtual std::string toJson() const = 0;

  /**
   * The JWS algorithm that this message validator can handle, if any.
   */
  virtual std::string algorithm() const = 0;

  /**
   * True if the given algorithm can be validated by this validtor.
   *
   * @param algorithm Name of the algorithm
   * @return true if the validator can verify a message signed with the given
   * algorithm
   */
  virtual bool Accepts(std::string algorithm) const;

  /**
   * Verfies that the given header is signed with the given signature.
   *
   * Calling this method is slower than the Verify method above.
   *
   * @param jsonHeader Deserialized JSON object contained in jose header
   * @param header the urlbase64 encoded JOSEHeader
   * @param signature the decoded signature
   */
  bool Validate(json jsonHeader, std::string header, std::string signature);
};

/**
 * A MessageSigner is capable of signing a JWS Joseheader
 */
class MessageSigner : public MessageValidator {
public:
  virtual ~MessageSigner() {}

  /**
   * Signs the given jose header.
   * if signature == 0, or *num_signate is less than what is needed for a
   * signature the method should return false, and num_signature should contain
   * the number of bytes needed to place the signature in.
   *
   * @param header the urlbase64 encoded JOSEHeader
   * @param num_header Number of bytes in the header
   * @param signature The binary signature. (Note base64 encoded).
   * @param num_signature The length of the signature.
   */
  virtual bool Sign(const uint8_t *header, size_t num_header,
                    uint8_t *signature, size_t *num_signature) = 0;

  /**
   * Creates the digital signature
   *
   * @param header the jose header to be signed
   * @return The signature
   */
  std::string Digest(std::string header);
};

typedef std::unique_ptr<MessageValidator> validator_ptr;
typedef std::unique_ptr<MessageSigner> signer_ptr;
#endif // SRC_INCLUDE_JWT_MESSAGEVALIDATOR_H_
