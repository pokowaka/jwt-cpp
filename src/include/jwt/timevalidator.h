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
#ifndef SRC_INCLUDE_JWT_TIMEVALIDATOR_H_
#define SRC_INCLUDE_JWT_TIMEVALIDATOR_H_

#include <string>
#include "jwt/claimvalidator.h"
class IClock;
class UtcClock;

class TimeValidator : public ClaimValidator {
 public:
  TimeValidator(const char *key, bool sign, uint64_t leeway);
  TimeValidator(const char *key, bool sign);
  TimeValidator(const char *key, bool sign, uint64_t leeway,
      IClock *clock);
  bool IsValid(const json_t *claimset) const;
  std::string toJson() const;

 private:
  bool sign_;
  uint64_t leeway_;
  IClock *clock_;
  static UtcClock utc_clock_;
};

/**
 * The exp (expiration time) claim identifies the expiration time on or after
 * which the JWT MUST NOT be accepted for processing. The processing of the exp
 * claim requires that the current date/time MUST be before the expiration
 * date/time listed in the exp claim. Implementers MAY provide for some small
 * leeway, usually no more than a few minutes, to account for clock skew. Its
 * value MUST be a number containing a NumericDate value. Use of this claim is
 * OPTIONAL.
 */
class ExpValidator : public TimeValidator {
 public:
  ExpValidator() : TimeValidator("exp", false) { }
  explicit ExpValidator(uint64_t leeway) : TimeValidator("exp", false, leeway) { }
  ExpValidator(uint64_t leeway, IClock *clock) : TimeValidator("exp", false, leeway, clock) { }
};

/**
 * The nbf (not before) claim identifies the time before which the JWT MUST NOT
 * be accepted for processing. The processing of the nbf claim requires that the
 * current date/time MUST be after or equal to the not-before date/time listed
 * in the nbf claim. Implementers MAY provide for some small leeway, usually no
 * more than a few minutes, to account for clock skew. Its value MUST be a
 * number containing a NumericDate value. Use of this claim is OPTIONAL.
 */
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
#endif  // SRC_INCLUDE_JWT_TIMEVALIDATOR_H_
