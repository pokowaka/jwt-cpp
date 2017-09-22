#include <iostream>
#include "jwt/jwt_all.h"
using json = nlohmann::json;

int main() {
    ExpValidator exp;
    HS256Validator signer("secret");

    // Now we use these validators to parse and verify the token we created
    // in the previous example
    std::string token =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
        "eyJpc3MiOiJmb28iLCJleHAiOjE0ODMyMjg4MDB9."
        "u3JTUx1tJDo601olQv0rHk4kGkKadIj3cvy-DDZKVRo";
    try {
        json header, payload;
        std::tie(header, payload) = JWT::Decode(token, &signer, &exp);
        std::cout << "You should not see this line" << std::endl;
    } catch (TokenFormatError &tfe) {
        // No data can be recovered..
    } catch (InvalidTokenError &tfe) {
        json header, payload;
        std::tie(header, payload) = JWT::Decode(token);
        std::cout << "Payload: " << payload << std::endl;
    }
}
