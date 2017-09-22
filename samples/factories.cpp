#include <iostream>
#include "jwt/jwt_all.h"
using json = nlohmann::json;

int main() {
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
        "  { \"HS256\" : { \"secret\" : \"secret!\" } }, "
        "  { \"HS512\" : { \"secret\" : \"supersafe\" } }"
        " ]"
        "}";
    validator_ptr message_validator(
        MessageValidatorFactory::Build(json_validators));

    // Now let's use these validators to parse and verify the token we created
    // with a previous sample.
    std::string str_token =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
        "eyJpc3MiOiJmb28iLCJleHAiOjE0ODMyMjg4MDB9."
        "u3JTUx1tJDo601olQv0rHk4kGkKadIj3cvy-DDZKVRo";
    try {
        ::json header, payload;
        std::tie(header, payload) = JWT::Decode(
            str_token, message_validator.get(), claim_validator.get());
        std::cout << "Header: " << header << std::endl;
        std::cout << "Payload: " << payload << std::endl;
    } catch (InvalidTokenError &tfe) {
        std::cout << tfe.what() << std::endl;
    }
}
