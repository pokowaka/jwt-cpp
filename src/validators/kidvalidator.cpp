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
#include "validators/kidvalidator.h"
#include <sstream>
#include <string>
#include <vector>


KidValidator::KidValidator() : algorithm_(NULL) { }

void KidValidator::Register(std::string kid, MessageValidator *validator) {
  validator_map_[kid] = validator;
  if (algorithm_ == NULL) {
    algorithm_ = validator->algorithm();
  }
  if (strcmp(algorithm_, validator->algorithm()) != 0) {
    throw std::logic_error("algorithm types have to be uniform");
  }
}

bool KidValidator::Verify(json_t *jsonHeader, const uint8_t *header, size_t num_header,
                          const uint8_t *signature, size_t num_signature) {
  json_t *kid = json_object_get(jsonHeader, "kid");
  if (!json_is_string(kid))
    return false;

  auto kidvalidator = validator_map_.find(json_string_value(kid));
  if (kidvalidator == validator_map_.end()) {
    return nullptr;
  }

  MessageValidator *validator = kidvalidator->second;
  return validator->Verify(jsonHeader, header, num_header, signature, num_signature);
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
