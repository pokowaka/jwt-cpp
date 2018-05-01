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
#ifndef SRC_INCLUDE_JWT_KIDVALIDATOR_H_
#define SRC_INCLUDE_JWT_KIDVALIDATOR_H_

#include "jwt/messagevalidator.h"
#include <map>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

/**
 * A simple dictionary to handle kid headers in a JWS token. The kid
 * header will be used to select the proper MessageValidator when this
 * validator is verfiying a token.
 *
 * The "kid" (key ID) Header Parameter is a hint indicating which key
 * was used to secure the JWS.  This parameter allows originators to
 * explicitly signal a change of key to recipients.  The structure of
 * the "kid" value is unspecified.  Its value MUST be a case-sensitive
 * string.
 */
class KidValidator : public MessageValidator {
public:
  KidValidator();

  /** Registers the given validator to handle the given key id.
   * @param kid The key id
   * @param validator The validator that should handle this key id
   */
  void Register(const std::string &kid, MessageValidator *validator);
  bool Verify(const json &jose, const uint8_t *header, size_t num_header,
              const uint8_t *signature, size_t num_signature) const override;
  bool Accepts(const json &jose) const override;
  std::string algorithm() const override { return algorithm_; }
  std::string toJson() const override;

private:
  std::map<std::string, MessageValidator *> validator_map_;
  std::string algorithm_;
};
#endif // SRC_INCLUDE_JWT_KIDVALIDATOR_H_
