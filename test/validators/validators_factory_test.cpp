#include "./constants.h"
#include "jwt/hmacvalidator.h"
#include "jwt/jwt.h"
#include "jwt/messagevalidatorfactory.h"
#include "jwt/nonevalidator.h"
#include "jwt/rsavalidator.h"
#include "gtest/gtest.h"
#include <fstream>
#include <string>

// Test for the various validators.
TEST(parse_test, proper_hmac) {
  for (int i = 0; i < 3; i++) {
    std::ostringstream json;
    json << "{ \"" << hmacs[i] << "\" : { \"secret\" : \"safe!\" } }";
    validator_ptr valid(MessageValidatorFactory::Build(json.str()));
    EXPECT_NE(nullptr, valid.get());
    EXPECT_STREQ(json.str().c_str(), valid->toJson().c_str());
    EXPECT_STREQ(hmacs[i], valid->algorithm().c_str());
  }
}

TEST(parse_signer_test, proper_hmac) {
  for (int i = 0; i < 3; i++) {
    std::ostringstream json;
    json << "{ \"" << hmacs[i] << "\" : { \"secret\" : \"safe!\" } }";
    validator_ptr valid(MessageValidatorFactory::BuildSigner(json.str()));
    EXPECT_NE(nullptr, valid.get());
    EXPECT_STREQ(json.str().c_str(), valid->toJson().c_str());
    EXPECT_STREQ(hmacs[i], valid->algorithm().c_str());
  }
}

TEST(parse_test, can_use_validator) {
  std::string json = "{ \"HS256\" : { \"secret\" : \"secret\" } }";
  validator_ptr valid(MessageValidatorFactory::Build(json));
  std::string strtoken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                         "eyJzdWIiOiJzdWJqZWN0IiwiZXhwIjoxNDM3NDMzMzk3fQ."
                         "VGPkHXap_i2zwUCxr7dsjBq7Nnx83h5dNGjzuifjpx8";

  ::json header, payload;
  std::tie(header, payload) = JWT::Decode(strtoken, valid.get());
  EXPECT_FALSE(header.empty());
  EXPECT_FALSE(payload.empty());
}

// Test for the various validators.
TEST(parse_test, proper_rsa) {
  for (int i = 0; i < 3; i++) {
    std::ostringstream json;
    json
        << "{ \"" << rs[i]
        << "\" : { \"public\" : \""
           "-----BEGIN PUBLIC KEY-----\\n"
           "MFswDQYJKoZIhvcNAQEBBQADSgAwRwJAdTI8v0w96101cfpvMHPruu1kqViskObb\\n"
           "Nnmy3FmhiJX0o5KNOKOEWKnTUoGfM7TbfV5WGRcXW37W4cBUQ2dLWwIDAQAB\\n"
           "-----END PUBLIC KEY-----"
           "\" } }";
    validator_ptr valid(MessageValidatorFactory::Build(json.str()));
    EXPECT_NE(nullptr, valid.get());
    EXPECT_STREQ(rs[i], valid->algorithm().c_str());
  }
}

TEST(parse_signer_test, rsa_missing_file) {
  std::string json = "{ \"RS256\" : { \"public\" : { \"fromfile\" : null } } }";
  ASSERT_THROW(MessageValidatorFactory::BuildSigner(json), std::logic_error);
}

// Test for the various validators.
TEST(parse_signer_test, proper_rsa) {
  for (int i = 0; i < 3; i++) {
    std::ostringstream json;
    json
        << "{ \"" << rs[i]
        << "\" : { \"public\" : \""
           "-----BEGIN PUBLIC KEY-----\\n"
           "MFswDQYJKoZIhvcNAQEBBQADSgAwRwJAdTI8v0w96101cfpvMHPruu1kqViskObb\\n"
           "Nnmy3FmhiJX0o5KNOKOEWKnTUoGfM7TbfV5WGRcXW37W4cBUQ2dLWwIDAQAB\\n"
           "-----END PUBLIC KEY-----"
           "\", \"private\" : \""
           "-----BEGIN RSA PRIVATE KEY-----\\n"
           "MIIEowIBAAKCAQEA4SWe3cgEULKiz2wP+fYqN2TxEx6DiL4rvyqZfl0CFpVMH7wC\\n"
           "ZqvglxOMtUzpdO7USdlFmyOEjtH1tioll9EAg6DMs0QrLgBj7U0XHRHeJcRrbYxm\\n"
           "HqtmtRxjEmLBpClJoYaJ2fEdeaVcV5D1+kWMIRLM1q3RNafb1Q62nwSyojgX09/X\\n"
           "+lWtkuX4NPwnn5NW13uhLyO96bANWMzPhYewwCsY7s7HCscNEhVTLQF0UmtYMgpn\\n"
           "kzrR9aibtmCZhf58ebn0VjtoYu3JzhzmvUK+E3OZb0xp3e2f464owRIvWTlTte9h\\n"
           "kDnkNKYoqY7fF/adwb8xDNZEAeYAwE0jC2tE3QIDAQABAoIBAQCsLgATba5XJHW8\\n"
           "GNETAL2CRXDThUdkIMMF3AcsiuZY7O4dasOPTyxffPTjhaEX6rlwjHdd0EjEjC7T\\n"
           "k+HR+2TgRO2mvqAi+utwg78EXTC9QzxAt9k05TGTmdTuL5YU+/oyS9hKUsmOyPYY\\n"
           "hWSHc/5ZIK6EEsNmvCszAaCJdadCxCF9r/jTkT2iWVtV1Zrh7+Z/azX+wWSBIcEW\\n"
           "Lbk6MGCt2z7mWGla4x7ToxhYWBhRdDxZ0R3VzG05e1Yjn1q2U5uxsSdBAPAISgeD\\n"
           "7LpnwMs9NcjGnVO2cUHfK1fL7tLpMlqTsyflEyvFuN2+WatY7eaFeI/jRBb3ezYF\\n"
           "IcNZD8eBAoGBAPnhgL1ZhpDZRJ+M/CjV0KQmbzoMyt5B38cDJ0VNZG/CObCMKwvI\\n"
           "kMisBwFZEyS1oiV2Lt//8tLDnrlvxQrKQLmEzI5kCbuh3EUiG/tMF4VmKB4+JR/2\\n"
           "TNsHCqeNuKmVjy+SYNkHDfO5MbdNBSSXaV4GuA1L3evzwTNOij39C8ThAoGBAOap\\n"
           "D7XOigmuGMeOiFcivtGmCuOKfS8ZqTV2tKBcu3kv8F9CeqAFp/Qznxn/M8oi91VN\\n"
           "rdDwkH9aClXXSjaj2FpWHCU+hQJUbzucClOf0VgExYsdwNwEDaVrwRbo+fCzt3Fy\\n"
           "IdChwV7AO9sSggcGWbavbCU7F/h1g/BLHx/njYN9AoGAdQIDJqclO+6BE7UQ3o5A\\n"
           "hJz6uFQFKs3t22K+oNT8kth/6wu3nGzuXwkuvpLXQ/lJVAFjMcDIE6lGSc7slYDf\\n"
           "jf+BSavOYu4IFtdCAwo+eVi8sGypNa4/jtBdTNgwADjoM353myiSf+3YOdz264t6\\n"
           "62x6Ar/jyvj5Hu1IDn7PZAECgYAdoYw+G8lJ0w6l3B6Rqwn+Xqk5b9oDCfXdw2ES\\n"
           "1LbUq57ibeTY18EqstL2gP1DM1i4oaD5nV3CrmtzeZO0DzpE6Jj3A+AMW5JqgvIk\\n"
           "qfw3pW1HIMxctzyVipEkg0tQa5XeQf4sEguIQ4Os8eS4SE2QFVr8MWoz5czMOqpF\\n"
           "6/YW9QKBgERgOD3W9BcecygPNZfGZSZRVF0j5LT0PDgKr/02CIPu2mo+2ej9GmBP\\n"
           "PnLXbe/R9SG8p2+Yh2ZfXn7FlXfr9a7MkzQWR/rpmxlDyzAyaJaI/vCBP+KknzPo\\n"
           "zBJNQZl5S6qKrqr0ypYs6ekAQ5MEe3twWWyXG2y1QgeMIs3BTnJ1\\n"
           "-----END RSA PRIVATE KEY-----"
           "\" } }";
    validator_ptr valid(MessageValidatorFactory::BuildSigner(json.str()));
    EXPECT_NE(nullptr, valid.get());
    EXPECT_STREQ(rs[i], valid->algorithm().c_str());
  }
}

// Test for the various validators.
TEST(parse_test, improper_rsa) {
  for (int i = 0; i < 3; i++) {
    std::ostringstream json;
    json
        << "{ \"" << rs[i]
        << "\" : { \"public\" : \""
           "-----BEGIN PUBLIC KEY-----\\n"
           "MFswDQYJK3ZIhvcNAQEBBQADSgAwRwJAdTI8v0w96101cfpvMHPruu1kqViskObb\\n"
           "Nnmy3FmhiJX0o5KNOKOEWKnTUoGfM7TbfV5WGRcXW37W4cBUQ2dLWwIDAQAB\\n"
           "-----END PUBLIC KEY-----"
           "\" } }";
    ASSERT_THROW(MessageValidatorFactory::Build(json.str()), std::logic_error);
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
    json << "{ \"" << rs[i]
         << "\" : { \"public\" : { \"fromfile\" : \"/tmp/test.key\" } } }";
    validator_ptr valid(MessageValidatorFactory::Build(json.str()));

    EXPECT_NE(nullptr, valid.get());
    EXPECT_STREQ(rs[i], valid->algorithm().c_str());
  }
}

// Test for the various validators.
TEST(parse_test, parse_set) {
  std::string json = "{ \"set\" : [ "
                     "{ \"HS256\" : { \"secret\" : \"safe\" } }, "
                     "{ \"HS512\" : { \"secret\" : \"supersafe\" } }"
                     " ] }";
  validator_ptr valid(MessageValidatorFactory::Build(json));
  EXPECT_NE(nullptr, valid.get());
  EXPECT_STREQ(json.c_str(), valid->toJson().c_str());
  EXPECT_TRUE(valid->Accepts("HS256"));
  EXPECT_FALSE(valid->Accepts("HS384"));
  EXPECT_TRUE(valid->Accepts("HS512"));
}

TEST(parse_test, parse_kid) {
  std::string json = "{ \"kid\" : { "
                     "\"key1\" : { \"HS256\" : { \"secret\" : \"key1\" } }, "
                     "\"key2\" : { \"HS256\" : { \"secret\" : \"key2\" } }, "
                     "\"key3\" : { \"HS256\" : { \"secret\" : \"key3\" } } "
                     "} }";
  validator_ptr valid(MessageValidatorFactory::Build(json));
  EXPECT_NE(nullptr, valid.get());
  EXPECT_STREQ(json.c_str(), valid->toJson().c_str());
  EXPECT_TRUE(valid->Accepts("HS256"));
  EXPECT_FALSE(valid->Accepts("HS512"));
}

TEST(parse_test, bad_kid) {
  // have to be of the same type..
  std::string json = "{ \"kid\" : { "
                     "\"key1\" : { \"HS256\" : { \"secret\" : \"key1\" } }, "
                     "\"key3\" : { \"HS512\" : { \"secret\" : \"key3\" } } "
                     "} }";
  ASSERT_THROW(MessageValidatorFactory::Build(json), std::logic_error);
}

TEST(parse_test, non_existing) {
  std::string json = "{ \"HS253\" : { \"secret\" : \"safe!\" } }";
  ASSERT_THROW(MessageValidatorFactory::Build(json), std::logic_error);
}

TEST(parse_test, too_many_properties) {
  std::string json =
      "{ \"HS256\" : { \"secret\" : \"safe!\" }, \"FOO\" : \"BAR\" }";
  ASSERT_THROW(MessageValidatorFactory::Build(json), std::logic_error);
}

TEST(parse_signer, too_many_properties) {
  std::string json =
      "{ \"HS256\" : { \"secret\" : \"safe!\" }, \"FOO\" : \"BAR\" }";
  ASSERT_THROW(MessageValidatorFactory::BuildSigner(json), std::logic_error);
}

TEST(parse_signer, non_existing_signer) {
  std::string json = "{ \"HS252\" : { \"secret\" : \"safe!\" }}";
  ASSERT_THROW(MessageValidatorFactory::BuildSigner(json), std::logic_error);
}

TEST(parse_test, non_secret) {
  std::string json = "{ \"HS256\" : { \"without_secret\" : \"safe!\" } }";
  ASSERT_THROW(MessageValidatorFactory::Build(json), std::logic_error);
}

TEST(parse_test, bad_json) {
  std::string json = "{ { \"HS256\" : { \"secret\" : \"safe!\" } }";
  ASSERT_THROW(MessageValidatorFactory::Build(json), std::logic_error);
}

TEST(parse_signer_test, bad_json) {
  std::string json = "{ { \"HS256\" : { \"secret\" : \"safe!\" } }";
  ASSERT_THROW(MessageValidatorFactory::BuildSigner(json), std::logic_error);
}

void roundtrip(MessageValidator *validator) {
  std::string json = validator->toJson();
  validator_ptr msg(MessageValidatorFactory::Build(json));
  EXPECT_STREQ(json.c_str(), msg->toJson().c_str());
}

void roundtrip_signer(MessageSigner *signer) {
  std::string json = signer->toJson();
  validator_ptr msg(MessageValidatorFactory::BuildSigner(json));
  EXPECT_STREQ(json.c_str(), msg->toJson().c_str());
}

TEST(parse, round_trip_none) {
  NoneValidator msg;
  roundtrip(&msg);
}

TEST(parse_signer, round_trip_none) {
  NoneValidator msg;
  roundtrip_signer(&msg);
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

TEST(parse_signer, round_trip_hs256) {
  HS256Validator msg("secret");
  roundtrip_signer(&msg);
}

TEST(parse_signer, round_trip_hs384) {
  HS384Validator msg("secret");
  roundtrip_signer(&msg);
}

TEST(parse_signer, round_trip_hs512) {
  HS512Validator msg("secret");
  roundtrip_signer(&msg);
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

TEST(parse_signer, round_trip_rs256) {
  RS256Validator msg(pubkey, privkey);
  roundtrip_signer(&msg);
}

TEST(parse_signer, round_trip_rs384) {
  RS384Validator msg(pubkey, privkey);
  roundtrip_signer(&msg);
}

TEST(parse_signer, round_trip_rs512) {
  RS512Validator msg(pubkey, privkey);
  roundtrip_signer(&msg);
}
