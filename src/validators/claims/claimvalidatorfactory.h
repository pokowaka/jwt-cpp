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
#ifndef SRC_VALIDATORS_CLAIMS_CLAIMVALIDATORFACTORY_H_
#define SRC_VALIDATORS_CLAIMS_CLAIMVALIDATORFACTORY_H_

#include <jansson.h>
#include <exception>
#include <string>
#include <vector>
#include "validators/claims/claimvalidator.h"

class ClaimValidatorFactory {
 public:
  static ClaimValidator *build(std::string fromJson);
  ~ClaimValidatorFactory();

 private:
  std::vector<std::string> buildlist(json_t *lst);
  std::vector<ClaimValidator*> buildvalidatorlist(json_t *json);
  ClaimValidator *build(json_t *fromJson);

  std::vector<ClaimValidator*> build_;
};

class ParsedClaimvalidator : public ClaimValidator {
 public:
  ParsedClaimvalidator(json_t *json, const std::vector<ClaimValidator*> &children,
      ClaimValidator *root);
  ~ParsedClaimvalidator();

  bool IsValid(const json_t *claimset) const override;
  std::string toJson() const override;

 private:
  json_t *json_;
  std::vector<ClaimValidator*> children_;
  ClaimValidator *root_;
};

#endif  // SRC_VALIDATORS_CLAIMS_CLAIMVALIDATORFACTORY_H_
