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
#ifndef SRC_INCLUDE_JWT_SETVALIDATOR_H_
#define SRC_INCLUDE_JWT_SETVALIDATOR_H_

#include "jwt/messagevalidator.h"
#include <map>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

/**
 * A validator that delegates to a set of registered
 * validators.
 */
class SetValidator : public MessageValidator {
public:
  explicit SetValidator(const std::vector<MessageValidator *> &msg);
  bool Verify(const json &jsonHeader, const uint8_t *header, size_t cHeader,
              const uint8_t *signature, size_t cSignature) const override;
  std::string algorithm() const override { return "SET"; }
  std::string toJson() const override;
  bool Accepts(const json &jose) const override;

private:
  std::map<std::string, MessageValidator *> validator_map_;
};

#endif // SRC_INCLUDE_JWT_SETVALIDATOR_H_
