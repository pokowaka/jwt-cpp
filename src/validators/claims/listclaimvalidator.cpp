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
#include <string.h>
#include <string>
#include <sstream>
#include <vector>
#include "validators/claims/listclaimvalidator.h"

ListClaimValidator::ListClaimValidator(const char *property,
    std::vector<std::string> accepted) : ClaimValidator(property),
  accepted_(accepted) { }

ListClaimValidator::ListClaimValidator(const char *property,
    const char *const *lst_accepted,
    const size_t num_accepted)
  :  ClaimValidator(property) {
    for (int i = 0; i < num_accepted; i++) {
      accepted_.push_back(std::string(lst_accepted[i]));
    }
  }

bool ListClaimValidator::IsValid(const json_t *claim) const {
  json_t *object = json_object_get(claim, property_);
  if (!json_is_string(object)) {
    return false;
  }

  const char *value = json_string_value(object);
  for (auto accept : accepted_) {
    if (accept == value)
      return true;
  }

  return false;
}

std::string ListClaimValidator::toJson() const {
  std::ostringstream msg;
  msg << "{ \"" << property() << "\" : [";
  int last = accepted_.size();
  for (auto accept : accepted_) {
    msg <<  "\"" << accept << "\"";
    if (--last != 0)
      msg << ", ";
  }
  msg << "] }";
  return msg.str();
}
