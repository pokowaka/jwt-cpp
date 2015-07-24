#include <jansson.h>
#include <string>
#include <sstream>
#include "gtest/gtest.h"
#include "jwt/jwt_all.h"

TEST(Sample, sign) {
  // Setup a signer
  HS256Validator signer("secret!");

  // Create the json payload that expires 01/01/2017 @ 12:00am (UTC)
  json_ptr json(json_pack("{ss, si}", "sub", "subject", "exp", 1483228800));

  // Let's encode the token to a char*
  str_ptr str_token(JWT::Encode(&signer, json.get()));

  EXPECT_NE(nullptr, str_token.get());
}

TEST(Sample, invalid_tokens) {
  // Improper formatted tokens will result in an exception;
  try {
    JWT::Decode("ceci n'est pas une jwt");
    FAIL();
  } catch (TokenFormatError &tfe) {

  }
}

TEST(Sample, payload_deserialize) {
  // Let's use the HS256 signer & validator.
  HS256Validator signer("secret");

  // Setup the json payload we want to use
  json_ptr json(json_pack("{ss, si}", "sub", "subject", "exp", time(NULL) + 360000));

  // Encode the jwt token.
  str_ptr str_token(JWT::Encode(&signer, json.get()));

  // Use the expiration validator
  ExpValidator exp;

  // Decode and validate the token
  try {
    jwt_ptr token(JWT::Decode(str_token.get(), &signer, &exp));
    const json_t* header = token->header();
    const json_t* payload = token->payload();
  } catch (TokenFormatError &tfe) {
    // Badly encoded token
    FAIL();
  }

}

TEST(Sample, from_json) {
  // Let's create a signed token, issued by foo that expires 01/01/2040 @ 12:00am (UTC)
  HS256Validator signer("safe");
  json_ptr json(json_pack("{ss, sI}", "iss", "foo", "exp", 2208988800));
  str_ptr str_token(JWT::Encode(&signer, json.get()));

  // Let's setup a claim validator where we will accept tokens that
  // are have been issues by either foo or bar
  // and have an optional expiration claim with a leeway of 32s.
  std::string json_claim =
      "{ \"all\" : "
          "  [ "
          "    { \"optional\" : { \"exp\" : { \"leeway\" : 32} } },"
          "    { \"iss\" : [\"foo\", \"bar\"] }"
          "  ]"
          "}";

  // Lets build the claim validator
  claim_ptr claim_validator(ClaimValidatorFactory::Build(json_claim));

  // Next we are going to setup the message validators. We will accept
  // the HS256 & HS512 validators with the given secrets.
  std::string json_validators =
      "{ \"set\" : [ "
          "  { \"HS256\" : { \"secret\" : \"safe\" } }, "
          "  { \"HS512\" : { \"secret\" : \"supersafe\" } }"
          " ]"
          "}";
  validator_ptr message_validator(MessageValidatorFactory::Build(json_validators));

  // Now let's use these validators to parse and verify the token we
  // created above
  jwt_ptr token;

  try {
    token.reset(JWT::Decode(str_token.get(), message_validator.get(), claim_validator.get()));
  } catch (InvalidTokenError &tfe) {
    // Badly token
    FAIL();
  }
}

TEST(Sample, kid) {
  // Let's create a signed token, issued by foo that expires 01/01/2040 @ 12:00am (UTC)
  HS256Validator signer("safe");
  json_ptr json(json_pack("{ss, sI}", "iss", "foo", "exp", 2208988800));

  // Lets add a header with a specific key id field set
  json_ptr keyid(json_pack("{ss}", "kid", "key_id_1"));
  str_ptr str_token(JWT::Encode(&signer, json.get(), keyid.get()));

  // Next we are going to setup the message validators.
  // We will accept the various key ids that are mapped to the
  // their corresponding validator.
  std::string json_validators =
      "{ \"kid\" : { "
          "  \"key_id_1\" :  { \"HS256\" : { \"secret\" : \"safe\" } }, "
          "  \"key_id_2\" :  { \"HS256\" : { \"secret\" : \"supersafe\" } }"
          " }"
          "}";
  validator_ptr message_validator(MessageValidatorFactory::Build(json_validators));

  // Now let's use these validators to parse and verify the token we
  // created above
  try {
    jwt_ptr token(JWT::Decode(str_token.get(), message_validator.get()));
  } catch (InvalidTokenError &ite) {
    FAIL();
  }
}
