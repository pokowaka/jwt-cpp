#include <jansson.h>
#include <string>
#include <sstream>
#include "gtest/gtest.h"
#include "jwt/jwt.h"
#include "util/allocators.h"
#include "util/clock.h"
#include "validators/claims/claimvalidatorfactory.h"
#include "validators/claims/timevalidator.h"
#include "validators/hmacvalidator.h"
#include "validators/messagevalidatorfactory.h"

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
  // Use a clock that return UTC time
  UtcClock clock;

  // Let's use the HS256 signer & validator.
  HS256Validator signer("secret");

  // Setup the json payload we want to use
  json_ptr json(json_pack("{ss, si}", "sub", "subject", "exp", clock.Now() + 3600));

  // Encode the jwt token.
  str_ptr str_token(JWT::Encode(&signer, json.get()));

  // Use the expiration validator
  ExpValidator exp;

  // Decode and validate the token
  jwt_ptr token;
  try {
    token.reset(JWT::Decode(str_token.get(), &signer, &exp));
  } catch (TokenFormatError *tfe) {
    // Badly encoded token
    FAIL();
  }

  if (!token->IsValid()) {
    // Claim validators say token is invalid
    FAIL();
  }

  if (!token->IsSigned()) {
    // JWT is not signed.
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
  claim_ptr claim_validator(ClaimValidatorFactory::build(json_claim));

  // Next we are going to setup the message validators. We will accept
  // the HS256 & HS512 validators with the given secrets.
  std::string json_validators =
      "{ \"set\" : [ "
          "  { \"HS256\" : { \"secret\" : \"safe\" } }, "
          "  { \"HS512\" : { \"secret\" : \"supersafe\" } }"
          " ]"
          "}";
  validator_ptr message_validator(MessageValidatorFactory::build(json_validators));

  // Now let's use these validators to parse and verify the token we
  // created above
  jwt_ptr token;

  try {
    token.reset(JWT::Decode(str_token.get(), message_validator.get(), claim_validator.get()));
  } catch (TokenFormatError *tfe) {
    // Badly encoded token
    FAIL();
  }

  if (!token->IsValid()) {
    // Claim validators say token is invalid
    FAIL();
  }

  if (!token->IsSigned()) {
    // JWT is not signed.
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
  validator_ptr message_validator(MessageValidatorFactory::build(json_validators));

  // Now let's use these validators to parse and verify the token we
  // created above
  jwt_ptr token(JWT::Decode(str_token.get(), message_validator.get()));

  if (token.get() == nullptr) {
    // Badly encoded token"
    FAIL();
  }

  if (!token->IsSigned()) {
    // JWT is not signed.
    FAIL();
  }

  // We don't care about claims..
}
