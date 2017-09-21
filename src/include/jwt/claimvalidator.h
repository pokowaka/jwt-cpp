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
#ifndef SRC_INCLUDE_JWT_CLAIMVALIDATOR_H_
#define SRC_INCLUDE_JWT_CLAIMVALIDATOR_H_

#include <jansson.h>
#include <string>
#include <vector>
#include <memory>
#include "jwt/jwt_error.h"
#include "jwt/json.hpp"

/**
 * An InvalidClaimError indicats that the payload in the
 * JWT could not be validated.
 */
class InvalidClaimError : public InvalidTokenError {
 public:
  explicit InvalidClaimError(std::string msg) : InvalidTokenError(msg) { }
};

/**
 * A ClaimValidator is capable of validating a JWT payload
 */
class ClaimValidator {
 public:
  using json = nlohmann::json;
  virtual ~ClaimValidator() {}

  /**
   * Returns true if this claim validator is able to validate
   * the given claim.
   *
   * @param claimset The set of claims to be validated
   * @return true if the claim is valid.
   * @throw InvalidClaimError if the token cannot be validated
   */
  virtual bool IsValid(const json_t *claimset) const = 0;

  virtual bool IsValid(const json *claimset) {
    std::unique_ptr<json_t> json_str(json_loads(claimset->dump().c_str(), JSON_REJECT_DUPLICATES, nullptr));
    return IsValid(json_str.get());
  };

  /**
   * A Json representation of this validator. This can
   * be used to reconstruct this validator using a ClaimValidatorFactory
   */
  virtual std::string toJson() const = 0;

  /**
   * The key in the payload this claim validator validates.
   */
  inline const char* property() const { return property_; }

 protected:
  explicit ClaimValidator(const char* property) : property_(property) {}
  const char* property_;
};

/**
 * An AllClaimValidator evaluates to true if all of its
 * child ClaimValidators evaluate to true.
 */
class AllClaimValidator : public ClaimValidator {
 public:
  AllClaimValidator(const ClaimValidator *const *lstClaims, const size_t numClaims);
  /**
   * Constructs a new AllClaimValidator with a list validators that need to
   * evaluate to true.
   * @param validators The list of claimvalidators that have to evaluate to true
   */
  explicit AllClaimValidator(std::vector<ClaimValidator*> validators);
  bool IsValid(const json_t *claimset) const;
  std::string toJson() const;

 private:
  std::vector<ClaimValidator*> validators_;
};

/**
 * An OptionalClaimValidator wraps a ClaimValidator and makes the wrapped
 * ClaimValidator optional. This evaluates to true when:
 * - The key required by the wrapped claimvalidator does not exist in the payload
 * - The wrapped claimvalidator evualtes to true
 */
class OptionalClaimValidator : public ClaimValidator {
 public:
  explicit OptionalClaimValidator(const ClaimValidator *inner);
  bool IsValid(const json_t *claimset) const;
  std::string toJson() const;

 private:
  const ClaimValidator *inner_;
};

/**
 * An AnyClaimValidator evaluates to true at least one of its
 * child ClaimValidators evaluates to true.
 */
class AnyClaimValidator :  public ClaimValidator {
 public:
  AnyClaimValidator(const ClaimValidator *const *lstClaims, const size_t numClaims);
  explicit AnyClaimValidator(std::vector<ClaimValidator*> validators);
  bool IsValid(const json_t *claimset) const;
  std::string toJson() const;

 private:
  std::vector<ClaimValidator*> validators_;
};

typedef std::unique_ptr<ClaimValidator> claim_ptr;
#endif  // SRC_INCLUDE_JWT_CLAIMVALIDATOR_H_
