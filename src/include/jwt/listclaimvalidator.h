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
#ifndef SRC_INCLUDE_JWT_LISTCLAIMVALIDATOR_H_
#define SRC_INCLUDE_JWT_LISTCLAIMVALIDATOR_H_

#include "jwt/claimvalidator.h"
#include <string>
#include <vector>

class ListClaimValidator : public ClaimValidator {
public:
  ListClaimValidator(const std::string &property,
                     std::vector<std::string> accepted);
  bool IsValid(const json &claim) const;
  std::string toJson() const;

protected:
  std::vector<std::string> accepted_;
};

/**
 * The iss (issuer) claim identifies the principal that issued the JWT. The
 * processing of this claim is generally application specific. The iss value is
 * a case-sensitive string containing a StringOrURI value. Use of this claim is
 * OPTIONAL.
 */
class IssValidator : public ListClaimValidator {
public:
  IssValidator(const std::vector<std::string> &accepted)
      : ListClaimValidator("iss", accepted) {}
};

/**
 * The sub (subject) claim identifies the principal that is the subject of the
 * JWT. The claims in a JWT are normally statements about the subject. The
 * subject value MUST either be scoped to be locally unique in the context of
 * the issuer or be globally unique. The processing of this claim is generally
 * application specific. The sub value is a case-sensitive string containing a
 * StringOrURI value. Use of this claim is OPTIONAL.
 */
class SubValidator : public ListClaimValidator {
public:
  SubValidator(const std::vector<std::string> &accepted)
      : ListClaimValidator("sub", accepted) {}
};

/**
 * The aud (audience) claim identifies the recipients that the JWT is intended
 * for. Each principal intended to process the JWT MUST identify itself with a
 * value in the audience claim. If the principal processing the claim does not
 * identify itself with a value in the aud claim when this claim is present,
 * then the JWT MUST be rejected. In the general case, the aud value is an array
 * of case-sensitive strings, each containing a StringOrURI value. In the
 * special case when the JWT has one audience, the aud value MAY be a single
 * case-sensitive string containing a StringOrURI value. The interpretation of
 * audience values is generally application specific. Use of this claim is
 * OPTIONAL.
 */
class AudValidator : public ListClaimValidator {
public:
  AudValidator(const std::vector<std::string> &accepted)
      : ListClaimValidator("aud", accepted) {}
  bool IsValid(const json &claim) const;
};
#endif // SRC_INCLUDE_JWT_LISTCLAIMVALIDATOR_H_
