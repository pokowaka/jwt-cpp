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
#include "validators/claims/claimvalidator.h"
#include <sstream>
#include <string>
#include <vector>
#include <iostream>

AllClaimValidator::AllClaimValidator(const ClaimValidator *const *lstClaims,
    const size_t numClaims) : ClaimValidator(NULL) {
  for (size_t i = 0; i < numClaims; i++) {
    validators_.push_back(const_cast<ClaimValidator*>(lstClaims[i]));
  }
}

AllClaimValidator::AllClaimValidator(std::vector<ClaimValidator*> validators) :
  ClaimValidator(NULL), validators_(validators)  { }

bool AllClaimValidator::IsValid(const json_t *claimset) const {
  for (auto validator : validators_) {
      if (!validator->IsValid(claimset))
        return false;
  }
  return true;
}

std::string AllClaimValidator::toJson() const {
  std::ostringstream msg;
  msg << "{ \"all\" : [ ";
  int num = validators_.size();
  for (auto validator : validators_) {
      msg << validator->toJson();
      if (--num != 0)
        msg << ", ";
  }
  msg << " ] }";
  return msg.str();
}

AnyClaimValidator::AnyClaimValidator(std::vector<ClaimValidator*> validators) :
  ClaimValidator(NULL), validators_(validators)  { }

AnyClaimValidator::AnyClaimValidator(const ClaimValidator *const *lstClaims, const size_t
    numClaims) : ClaimValidator(NULL) {
      for (size_t i = 0; i < numClaims; i++) {
        validators_.push_back(const_cast<ClaimValidator*>(lstClaims[i]));
      }
    }

bool AnyClaimValidator::IsValid(const json_t *claimset) const {
  for (auto validator : validators_) {
      try {
        if (validator->IsValid(claimset))
          return true;
      } catch(InvalidClaimError ice) {

      }
  }
  throw InvalidClaimError("None of the children validate");
}

std::string AnyClaimValidator::toJson() const {
  std::ostringstream msg;
  msg << "{ \"any\" : [ ";
  int num = validators_.size();
  for (auto validator : validators_) {
      msg << validator->toJson();
      if (--num != 0)
        msg << ", ";
  }
  msg << " ] }";
  return msg.str();
}

OptionalClaimValidator::OptionalClaimValidator(const ClaimValidator *inner) : ClaimValidator
(inner->property()), inner_(inner) { }

bool OptionalClaimValidator::IsValid(const json_t *claimset) const  {
  return json_object_get(claimset, property_) == NULL || inner_->IsValid(claimset);
}

std::string OptionalClaimValidator::toJson() const {
  std::ostringstream msg;
  msg << "{ \"optional\" : " << inner_->toJson() << " }";
  return msg.str();
}

