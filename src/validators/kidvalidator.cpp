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
#include "jwt/kidvalidator.h"
#include <sstream>
#include <string>
#include <vector>

KidValidator::KidValidator() : algorithm_("") {}

void KidValidator::Register(const std::string &kid, MessageValidator *validator) {
  validator_map_[kid] = validator;
  if (algorithm_.empty()) {
    algorithm_ = validator->algorithm();
  }
  // This is due to the accept call not looking at the whole jose header.
  if (algorithm_ != validator->algorithm()) {
    throw std::logic_error("algorithm types have to be uniform");
  }
}

bool KidValidator::Verify(const json &jsonHeader, const uint8_t *header,
                          size_t num_header, const uint8_t *signature,
                          size_t num_signature) const {
  if (!jsonHeader.count("kid") || !jsonHeader["kid"].is_string())
    return false;

  auto kidvalidator = validator_map_.find(jsonHeader["kid"].get<std::string>());
  if (kidvalidator == validator_map_.end()) {
    return false;
  }

  MessageValidator *validator = kidvalidator->second;
  return validator->Verify(jsonHeader, header, num_header, signature,
                           num_signature);
}

std::string KidValidator::toJson() const {
  std::ostringstream msg;
  msg << "{ \"kid\" : { ";
  int idx = 0;
  for (const auto &validator : validator_map_) {
    if (idx++ > 0) {
      msg << ", ";
    }
    msg << "\"" << validator.first << "\" : ";
    msg << validator.second->toJson();
  }
  msg << " } }";
  return msg.str();
}
