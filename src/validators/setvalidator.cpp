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
#include "validators/setvalidator.h"
#include <sstream>
#include <string>
#include <vector>

SetValidator::SetValidator(std::vector<MessageValidator*> validators) {
  for (auto validator : validators) {
    validator_map_[validator->algorithm()] = validator;
  }
}

bool SetValidator::Verify(json_t *jsonHeader, const uint8_t *header, size_t num_header,
                          const uint8_t *signature, size_t num_signature) {
  json_t* algname = json_object_get(jsonHeader, "alg");
  if (!json_is_string(algname)) {
    return  false;
  }

  auto alg = validator_map_.find(json_string_value(algname));
  if (alg == validator_map_.end()) {
    return nullptr;
  }

  MessageValidator* validator = alg->second;
  return validator->Verify(nullptr, header, num_header, signature, num_signature);
}


bool SetValidator::Accepts(const char* algorithm) const {
  auto alg = validator_map_.find(algorithm);
  return  alg != validator_map_.end();
}

std::string SetValidator::toJson() const {
  std::ostringstream msg;
  msg << "{ \"set\" : [ ";
  int idx = 0;
  for (const auto &validator : validator_map_) {
    if (idx++ > 0) {
      msg << ", ";
    }
    msg << validator.second->toJson();
  }
  msg << " ] }";
  return msg.str();
}
