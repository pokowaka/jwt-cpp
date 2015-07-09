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
//
// Created by Erwin Jansen on 7/8/15.
//

#ifndef SRC_VALIDATORS_LISTCLAIMVALIDATOR_H_
#define SRC_VALIDATORS_LISTCLAIMVALIDATOR_H_

#include "validators/claimvalidator.h"

class ListClaimValidator : public ClaimValidator {
 public:
  ListClaimValidator(const char *key, const char *const *lst_accepted, const size_t num_accepted);
  bool IsValid(const json_t *claimset) const override;

 private:
  const char *const *lst_accepted_;
  const char *key_;
  const size_t num_accepted_;
};

class IssValidator : public ListClaimValidator {
 public:
  IssValidator(const char *const *lst_accepted, const size_t num_accepted) : ListClaimValidator("iss", lst_accepted,
      num_accepted) { }
};

class SubValidator : public ListClaimValidator {
 public:
  SubValidator(const char *const *lst_accepted, const size_t num_accepted) : ListClaimValidator("sub", lst_accepted,
      num_accepted) { }
};


class AudValidator : public ListClaimValidator {
 public:
  AudValidator(const char *const *lst_accepted, const size_t num_accepted) : ListClaimValidator("aud", lst_accepted,
      num_accepted) { }
};
#endif  // SRC_VALIDATORS_LISTCLAIMVALIDATOR_H_
