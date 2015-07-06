#include "jwt.h"
#include <memory>
#include <string>

#include "base64.h"
#include "jansson.h"

bool Jwt::decode(std::string token) {

  // Verify that the JWT contains at least one period ('.') character.
  std::size_t found = token.find('.');
  if (found == std::string::npos) {
    return false;
  }

  // Let the Encoded JOSE Header be the portion of the JWT before the first period ('.') character.
  std::string joseHeader = token.substr(0, found);

  // Base64url decode the Encoded JOSE Header following the restriction that no line breaks,
  // whitespace, or other additional characters have been used.
  size_t cOut = 1 +  ((joseHeader.size()/3) + (joseHeader.size() % 3 > 0)) * 4;
  std::unique_ptr<char> pOut(new char[cOut]);

  if (UrlEncode::decode(joseHeader.c_str(), joseHeader.size(), pOut.get(), &cOut)) {
    return false;
  }
  // Let's make sure we are null terminated..
  pOut.get()[cOut-1] = 0;

  // Verify that the resulting octet sequence is a UTF-8-encoded representation of a
  // completely valid JSON object conforming to RFC 7159 [RFC7159]; let the JOSE Header
  // be this JSON object.
  json_t *root;
  json_error_t error;

  root = json_loads(pOut.get(), 0, &error);

  if (!root) {
    return false;
  }

  //
  // Verify that the resulting JOSE Header includes only parameters and values whose syntax and
  // semantics are both understood and supported or that are specified as being ignored when not
  // understood.

  // Determine whether the JWT is a JWS or a JWE using any of the methods described in
  // Section 9 of [JWE].
  // We will simply check if the "enc" member exists..


  // Depending upon whether the JWT is a JWS or JWE, there are two cases:
  // If the JWT is a JWS, follow the steps specified in [JWS] for validating
  // a JWS. Let the Message be the result of base64url decoding the JWS Payload.
  // Else, if the JWT is a JWE, follow the steps specified in [JWE] for
  // validating a JWE. Let the Message be the resulting plaintext.
  // If the JOSE Header contains a cty (content type) value of JWT, then the
  // Message is a JWT that was the subject of nested signing or encryption operations.
  // In this case, return to Step 1, using the Message as the JWT.
  // Otherwise, base64url decode the Message following the restriction that no
  // line breaks, whitespace, or other additional characters have been used.
  // Verify that the resulting octet sequence is a UTF-8-encoded representation
  // of a completely valid JSON object conforming to RFC 7159 [RFC7159]; let the JWT
  // Claims Set be this JSON object.
  //
  return false;
}
