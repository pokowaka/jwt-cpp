#include <iostream>
#include "jwt/jwt_all.h"
using json = nlohmann::json;

int main() {
    ExpValidator exp;
    HS256Validator signer("secret!");

    // Now let's use these validators to parse and verify the token we created
    // in the previous example
    std::string str_token =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
        "eyJpc3MiOiJmb28iLCJleHAiOjE0ODMyMjg4MDB9."
        "u3JTUx1tJDo601olQv0rHk4kGkKadIj3cvy-DDZKVRo";
    try {
        // Decode and validate the token
        ::json header, payload;

        std::tie(header, payload) = JWT::Decode(str_token, &signer, &exp);
        std::cout << "Header: " << header << std::endl;
        std::cout << "Payload: " << payload << std::endl;
    } catch (InvalidTokenError &tfe) {
        // An invalid token
        std::cout << "Validation failed: " << tfe.what() << std::endl;
    }
}
