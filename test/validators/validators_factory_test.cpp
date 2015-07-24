#include <string>
#include <fstream>
#include "gtest/gtest.h"
#include "./constants.h"
#include "jwt/jwt.h"
#include "jwt/hmacvalidator.h"
#include "jwt/messagevalidatorfactory.h"
#include "jwt/rsavalidator.h"
#include "jwt/nonevalidator.h"

// Test for the various validators.
TEST(parse_test, proper_hmac) {
  for (int i = 2; i > 0; i--) {
    std::ostringstream json;
    json << "{ \"" << hmacs[i] << "\" : { \"secret\" : \"safe!\" } }";
    validator_ptr valid(MessageValidatorFactory::Build(json.str()));
    EXPECT_NE(nullptr, valid.get());
    EXPECT_STREQ(json.str().c_str(), valid->toJson().c_str());
    EXPECT_STREQ(hmacs[i], valid->algorithm());
  }
}

TEST(parse_test, can_use_validator) {
  std::string json = "{ \"HS256\" : { \"secret\" : \"secret\" } }";
  validator_ptr valid(MessageValidatorFactory::Build(json));
  std::string strtoken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiJzdWJqZWN0IiwiZXhwIjoxNDM3NDMzMzk3fQ."
    "VGPkHXap_i2zwUCxr7dsjBq7Nnx83h5dNGjzuifjpx8";

  jwt_ptr token(JWT::Decode(strtoken, valid.get()));
  EXPECT_NE(nullptr, token.get());
}

// Test for the various validators.
TEST(parse_test, proper_rsa) {
  for (int i = 0; i < 3; i++) {
    std::ostringstream json;
    json << "{ \"" << rs[i] << "\" : { \"public\" : \""
        "-----BEGIN PUBLIC KEY-----\\n"
        "MFswDQYJKoZIhvcNAQEBBQADSgAwRwJAdTI8v0w96101cfpvMHPruu1kqViskObb\\n"
        "Nnmy3FmhiJX0o5KNOKOEWKnTUoGfM7TbfV5WGRcXW37W4cBUQ2dLWwIDAQAB\\n"
        "-----END PUBLIC KEY-----"
        "\" } }";
    validator_ptr valid(MessageValidatorFactory::Build(json.str()));
    EXPECT_NE(nullptr, valid.get());
    EXPECT_STREQ(rs[i], valid->algorithm());
  }
}

// Test for the various validators.
TEST(parse_test, proper_rsa_from_file) {
  std::ofstream out("/tmp/test.key");
  out << "-----BEGIN PUBLIC KEY-----\n"
      "MFswDQYJKoZIhvcNAQEBBQADSgAwRwJAdTI8v0w96101cfpvMHPruu1kqViskObb\n"
      "Nnmy3FmhiJX0o5KNOKOEWKnTUoGfM7TbfV5WGRcXW37W4cBUQ2dLWwIDAQAB\n"
      "-----END PUBLIC KEY-----";
  out.close();

  for (int i = 0; i < 3; i++) {
    std::ostringstream json;
    json << "{ \"" << rs[i] << "\" : { \"public\" : { \"fromfile\" : \"/tmp/test.key\" } } }";
    validator_ptr valid(MessageValidatorFactory::Build(json.str()));

    EXPECT_NE(nullptr, valid.get());
    EXPECT_STREQ(rs[i], valid->algorithm());
  }
}

// Test for the various validators.
TEST(parse_test, parse_set) {
  const char *json = "{ \"set\" : [ "
      "{ \"HS256\" : { \"secret\" : \"safe\" } }, "
      "{ \"HS512\" : { \"secret\" : \"supersafe\" } }"
      " ] }";
  validator_ptr valid(MessageValidatorFactory::Build(json));
  EXPECT_NE(nullptr, valid.get());
  EXPECT_STREQ(json, valid->toJson().c_str());
  EXPECT_TRUE(valid->Accepts("HS256"));
  EXPECT_FALSE(valid->Accepts("HS384"));
  EXPECT_TRUE(valid->Accepts("HS512"));
}

TEST(parse_test, parse_kid) {
  const char *json = "{ \"kid\" : { "
      "\"key1\" : { \"HS256\" : { \"secret\" : \"key1\" } }, "
      "\"key2\" : { \"HS256\" : { \"secret\" : \"key2\" } }, "
      "\"key3\" : { \"HS256\" : { \"secret\" : \"key3\" } } "
      "} }";
  validator_ptr valid(MessageValidatorFactory::Build(json));
  EXPECT_NE(nullptr, valid.get());
  EXPECT_STREQ(json, valid->toJson().c_str());
  EXPECT_TRUE(valid->Accepts("HS256"));
  EXPECT_FALSE(valid->Accepts("HS512"));
}

TEST(parse_test, bad_kid) {
  // have to be of the same type..
  const char *json = "{ \"kid\" : { "
      "\"key1\" : { \"HS256\" : { \"secret\" : \"key1\" } }, "
      "\"key3\" : { \"HS512\" : { \"secret\" : \"key3\" } } "
      "} }";
  ASSERT_THROW(MessageValidatorFactory::Build(json), std::logic_error);
}

TEST(parse_test, non_existing) {
  const char *json = "{ \"HS253\" : { \"secret\" : \"safe!\" } }";
  ASSERT_THROW(MessageValidatorFactory::Build(json), std::logic_error);
}

TEST(parse_test, non_secret) {
  const char *json = "{ \"HS253\" : { \"without_secret\" : \"safe!\" } }";
  ASSERT_THROW(MessageValidatorFactory::Build(json), std::logic_error);
}

TEST(parse_test, bad_json) {
  const char *json = "{ { \"HS256\" : { \"secret\" : \"safe!\" } }";
  ASSERT_THROW(MessageValidatorFactory::Build(json), std::logic_error);
}

void roundtrip(MessageValidator *validator) {
  std::string json = validator->toJson();
  validator_ptr msg(MessageValidatorFactory::Build(json));
  EXPECT_STREQ(json.c_str(), msg->toJson().c_str());
}

TEST(parse, round_trip_none) {
  NoneValidator msg;
  roundtrip(&msg);
}

TEST(parse, round_trip_hs256) {
  HS256Validator msg("secret");
  roundtrip(&msg);
}

TEST(parse, round_trip_hs384) {
  HS384Validator msg("secret");
  roundtrip(&msg);
}

TEST(parse, round_trip_hs512) {
  HS512Validator msg("secret");
  roundtrip(&msg);
}

TEST(parse, round_trip_rs256) {
  RS256Validator msg(pubkey);
  roundtrip(&msg);
}

TEST(parse, round_trip_rs384) {
  RS384Validator msg(pubkey);
  roundtrip(&msg);
}


TEST(parse, round_trip_rs512) {
  RS512Validator msg(pubkey);
  roundtrip(&msg);
}
