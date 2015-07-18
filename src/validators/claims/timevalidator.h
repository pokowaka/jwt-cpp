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
#ifndef SRC_VALIDATORS_CLAIMS_TIMEVALIDATOR_H_
#define SRC_VALIDATORS_CLAIMS_TIMEVALIDATOR_H_

#include <string>
#include "validators/claims/claimvalidator.h"
#include "util/clock.h"

class TimeValidator : public ClaimValidator {
 public:
  TimeValidator(const char *key, bool sign, uint64_t leeway) : TimeValidator(key, sign, leeway,
      &utc_clock_) { }
  TimeValidator(const char *key, bool sign) : TimeValidator(key, sign, 120) { }
  TimeValidator(const char *key, bool sign, uint64_t leeway, IClock *clock) : ClaimValidator(key), sign_
      (sign)
      , leeway_(leeway), clock_(clock) { }
  bool IsValid(const json_t *claimset) const override;
  std::string toJson() const override;

 private:
  bool sign_;
  uint64_t leeway_;
  IClock *clock_;
  static UtcClock utc_clock_;
};


class ExpValidator : public TimeValidator {
 public:
  ExpValidator() : TimeValidator("exp", false) { }
  explicit ExpValidator(uint64_t leeway) : TimeValidator("exp", false, leeway) { }
  ExpValidator(uint64_t leeway, IClock *clock) : TimeValidator("exp", false, leeway, clock) { }
};

class NbfValidator : public TimeValidator {
 public:
  NbfValidator() : TimeValidator("nbf", true) { }
  explicit NbfValidator(uint64_t leeway) : TimeValidator("nbf", true, leeway) { }
  NbfValidator(uint64_t leeway, IClock *clock) : TimeValidator("nbf", true, leeway, clock) { }
};

class IatValidator : public TimeValidator {
 public:
  IatValidator() : TimeValidator("iat", true) { }
  explicit IatValidator(uint64_t leeway) : TimeValidator("iat", true, leeway) { }
  IatValidator(uint64_t leeway, IClock *clock) : TimeValidator("iat", true, leeway, clock) { }
};
#endif  // SRC_VALIDATORS_CLAIMS_TIMEVALIDATOR_H_
