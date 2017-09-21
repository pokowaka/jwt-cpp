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
#include "jwt/timevalidator.h"
#include "jwt/jwt_error.h"
#include "private/clock.h"
#include <sstream>
#include <string>

UtcClock TimeValidator::utc_clock_ = UtcClock();
TimeValidator::TimeValidator(const char *key, bool sign, uint64_t leeway)
    : TimeValidator(key, sign, leeway, &utc_clock_) {}
TimeValidator::TimeValidator(const char *key, bool sign)
    : TimeValidator(key, sign, 0) {}
TimeValidator::TimeValidator(const char *key, bool sign, uint64_t leeway,
                             IClock *clock)
    : ClaimValidator(key), sign_(sign), leeway_(leeway), clock_(clock) {}

bool TimeValidator::IsValid(const json &claim) const {
  if (!claim.count(property_) || !claim[property_].is_number()) {
    throw InvalidClaimError(std::string("Missing claim: ") += property_);
  }

  int64_t time = claim[property_].get<int64_t>();
  if (time < 0) {
    throw InvalidClaimError(std::string("Negative time for: ") += property_);
  }

  int64_t diff = clock_->Now() - time;
  int64_t min = diff - leeway_;
  int64_t max = diff + leeway_;

  if (sign_) {
    if (!(min >= 0 || max >= 0)) {
      throw InvalidClaimError(std::string("Failed: ") += property_);
    }
    return true;
  }
  if (!(min <= 0 || max <= 0)) {
    throw InvalidClaimError(std::string("Failed: ") += property_);
  }

  return true;
}

std::string TimeValidator::toJson() const {
  std::ostringstream msg;
  msg << "{ \"" << property() << "\" : ";
  if (leeway_ == 0) {
    msg << "null";
  } else {
    msg << "{ \"leeway\" : " << std::to_string(leeway_) << " }";
  }
  msg << " }";
  return msg.str();
}
