#include <string>
#include "gtest/gtest.h"
#include "jwt/jwt_all.h"
#include "constants.h"

// Test for the various validators.
TEST(parse_test, proper_exp) {
  std::string json = "{ \"exp\" : null }";
  claim_ptr valid(ClaimValidatorFactory::Build(json));
  EXPECT_NE(nullptr, valid.get());
  EXPECT_STREQ("exp", valid->property());
}

TEST(parse_test, iss_not_a_list) {
  std::string json = "{ \"iss\" : { \"foo\" : \"bar\"} }";
  ASSERT_THROW(ClaimValidatorFactory::Build(json), std::logic_error);
}

TEST(parse_test, any) {
  std::string json =
      "{ \"any\" : [ \n"
          "  { \"optional\" : { \"exp\" : { \"leeway\" : 32} } },\n"
          "  { \"iss\" : [\"foo\", \"bar\"] }\n"
          "] \n"
          "}";
  claim_ptr valid(ClaimValidatorFactory::Build(json));
  EXPECT_NE(nullptr, valid.get());
  EXPECT_STREQ(NULL, valid->property());
}

TEST(parse_test, any_not_a_list) {
  std::string json = "{ \"any\" : { \"xx\" : \"zz\" }}";
  ASSERT_THROW(ClaimValidatorFactory::Build(json), std::logic_error);
}

TEST(parse_test, iss_not_a_stringlist) {
  std::string json = "{ \"iss\" : [ { \"foo\" : \"bar\" } , \"zz\" ]}";
  ASSERT_THROW(ClaimValidatorFactory::Build(json), std::logic_error);
}

TEST(parse_test, optional_exp) {
  std::string json = "{ \"optional\" : { \"exp\" : { \"leeway\" : 32} } }";
  claim_ptr valid(ClaimValidatorFactory::Build(json));
  EXPECT_NE(nullptr, valid.get());
  EXPECT_STREQ("exp", valid->property());
  json_ptr iat(json_pack("{si}", "iat", 9));
  EXPECT_TRUE(valid->IsValid(iat.get()));
}

TEST(parse_test, optional_bad) {
  std::string json = "{ \"optional\" : { \"foo\" : \"bar\" } }";
  ASSERT_THROW(ClaimValidatorFactory::Build(json), std::logic_error);
}

TEST(parse_test, optional_empty) {
  std::string json = "{ \"optional\" : null }";
  ASSERT_THROW(ClaimValidatorFactory::Build(json), std::logic_error);
}

TEST(parse_test, optional_inner_bad) {
  std::string json = "{ \"optional\" : { \"elxp\" : null } }";
  ASSERT_THROW(ClaimValidatorFactory::Build(json), std::logic_error);
}

TEST(parse_test, double_properties) {
  std::string json =  "{ \"exp\" : null, \"nbf\" : null }";
  ASSERT_THROW(ClaimValidatorFactory::Build(json), std::logic_error);
}

TEST(parse_test, bad_type) {
  std::string json =
      "{ \"all\" : [ \n"
          "  \"optional\" : { \"exp\" : { \"leeway\" : 32} }, \n"
          "  \"iss\" : [\"foo\", \"bar\"]] \n"
          "}";
  ASSERT_THROW(ClaimValidatorFactory::Build(json), std::logic_error);
}

void roundtrip(ClaimValidator *claimValidator) {
  std::string json = claimValidator->toJson();
  claim_ptr claim(ClaimValidatorFactory::Build(json));
  EXPECT_STREQ(json.c_str(), claim->toJson().c_str());
}

TEST(parse, round_trip_exp) {
  ExpValidator exp;
  roundtrip(&exp);
}

TEST(parse, round_trip_exp_leeway) {
  ExpValidator exp(120);
  roundtrip(&exp);
}

TEST(parse, round_trip_nbf) {
  NbfValidator validator;
  roundtrip(&validator);
}

TEST(parse, round_trip_iat) {
  IatValidator validator;
  roundtrip(&validator);
}

const char *const lst[] = {"foo", "bar"};

TEST(parse, round_trip_aud) {
  AudValidator validator(lst, 2);
  roundtrip(&validator);
}

TEST(parse, round_trip_iss) {
  IssValidator validator(lst, 2);
  roundtrip(&validator);
}

TEST(parse, round_trip_sub) {
  SubValidator validator(lst, 2);
  roundtrip(&validator);
}


TEST(parse, round_trip_all) {
  SubValidator val1(lst, 2);
  AudValidator val2(lst, 2);

  ClaimValidator *claims[] = {&val1, &val2};
  AllClaimValidator validator(claims, 2);
  roundtrip(&validator);
}

TEST(parse, round_trip_any) {
  SubValidator val1(lst, 2);
  AudValidator val2(lst, 2);

  ClaimValidator *claims[] = {&val1, &val2};
  AnyClaimValidator validator(claims, 2);
  roundtrip(&validator);
}

TEST(parse, round_trip_option) {
  SubValidator val1(lst, 2);
  OptionalClaimValidator validator(&val1);
  roundtrip(&validator);
}
