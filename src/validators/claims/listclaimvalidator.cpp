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
#include "jwt/listclaimvalidator.h"
#include "jwt/jwt_error.h"
#include <sstream>
#include <string.h>
#include <string>
#include <vector>

ListClaimValidator::ListClaimValidator(std::string property,
                                       std::vector<std::string> accepted)
    : ClaimValidator(property), accepted_(accepted) {}

bool ListClaimValidator::IsValid(const json claim) const {
  if (!claim.count(property_)) {
    throw InvalidClaimError(std::string("Missing: ") += property_);
  }

  std::string value = claim[property_].get<std::string>();
  for (auto accept : accepted_) {
    if (accept == value)
      return true;
  }

  throw InvalidClaimError(std::string("Invalid: ") += property_);
}

std::string ListClaimValidator::toJson() const {
  std::ostringstream msg;
  msg << "{ \"" << property() << "\" : [";
  int last = accepted_.size();
  for (auto accept : accepted_) {
    msg << "\"" << accept << "\"";
    if (--last != 0)
      msg << ", ";
  }
  msg << "] }";
  return msg.str();
}

bool AudValidator::IsValid(const json claim) const {
  if (!claim.count(property_)) {
    throw InvalidClaimError(std::string("aud not a string/array: "));
  }

  json object = claim[property_];
  if (!object.is_string() || !object.is_array()) {
    throw InvalidClaimError(std::string("aud not a string/array: "));
  }
  if (object.is_string()) {
    return ListClaimValidator::IsValid(claim);
  }

  for (json::iterator it = object.begin(); it != object.end(); ++it) {
    for (auto accept : accepted_) {
      if (accept == *it)
        return true;
    }
  }
  throw InvalidClaimError(std::string("Invalid: ") += property_);
}
