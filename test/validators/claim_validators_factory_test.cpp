#include <string>
#include "gtest/gtest.h"
#include "validators/claims/claimvalidatorfactory.h"
#include "util/allocators.h"

// Test for the various validators.
TEST(parse_test, proper_exp) {
  std::string json = "{ \"exp\" : null }";
  claim_ptr valid(ClaimValidatorFactory::build(json));
  EXPECT_NE(nullptr, valid.get());
  EXPECT_STREQ("exp", valid->property());
}

TEST(parse_test, optional_exp) {
  std::string json = "{ \"optional\" : { \"exp\" : { \"leeway\" : 32} } }";
  claim_ptr valid(ClaimValidatorFactory::build(json));
  EXPECT_NE(nullptr, valid.get());
  EXPECT_STREQ("exp", valid->property());
}

TEST(parse_test, any) {
  std::string json =
      "{ \"any\" : [ \n"
          "  { \"optional\" : { \"exp\" : { \"leeway\" : 32} } },\n"
          "  { \"iss\" : [\"foo\", \"bar\"] }\n"
          "] \n"
          "}";
  claim_ptr valid(ClaimValidatorFactory::build(json));
  EXPECT_NE(nullptr, valid.get());
  EXPECT_STREQ(NULL, valid->property());
}


TEST(parse_test, bad_type) {
  std::string json =
      "{ \"all\" : [ \n"
          "  \"optional\" : { \"exp\" : { \"leeway\" : 32} }, \n"
          "  \"iss\" : [\"foo\", \"bar\"]] \n"
          "}";
  ASSERT_THROW(ClaimValidatorFactory::build(json), std::logic_error);
}

