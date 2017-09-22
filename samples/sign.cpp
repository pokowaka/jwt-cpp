#include <iostream>
#include "jwt/jwt_all.h"
using json = nlohmann::json;

int main() {
    // Setup a signer
    HS256Validator signer("secret!");

    // Create the json payload that expires 01/01/2017 @ 12:00am (UTC)
    json payload = {{"sub", "subject"}, {"exp", 1483228800}};

    // Let's encode the token to a string
    auto token = JWT::Encode(signer, payload);

    std::cout << token << std::endl;
}
