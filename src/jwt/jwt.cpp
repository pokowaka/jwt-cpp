// Copyright (c) 2015 Erwin Jansen
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#include "jwt/jwt.h"
#include "jwt/allocators.h"
#include "jwt/jwt_error.h"
#include "private/base64.h"
#include <jansson.h>
#include <string>

using json = nlohmann::json;

JWT::JWT(json header_claims, json payload_claims)
    : header_(header_claims), payload_(payload_claims) {}

JWT::~JWT() {}

std::string JWT::Encode(MessageSigner *validator, json payload, json header) {
  header["typ"] = "JWT";
  header["alg"] = validator->algorithm();
  auto header_enc = Base64Encode::EncodeUrl(header.dump());
  auto payload_enc = Base64Encode::EncodeUrl(payload.dump());
  auto signed_area = header_enc + '.' + payload_enc;
  auto digest = validator->Digest(signed_area);
  return (signed_area + '.' + Base64Encode::EncodeUrl(digest));
}

JWT *JWT::Decode(std::string jwsToken, MessageValidator *verifier,
                 ClaimValidator *validator) {
  return Decode(jwsToken.c_str(), jwsToken.size(), verifier, validator);
}

JWT *JWT::Decode(const char *jws_token, size_t num_jws_token,
                 MessageValidator *verifier, ClaimValidator *validator) {
  int idx = 0;
  const char *header = jws_token, *payload = jws_token, *signature = jws_token,
             *it = jws_token;
  size_t num_header = 0, num_payload = 0, num_signature = 0;

  for (; it < (jws_token + num_jws_token) && idx < 3; it++) {
    if (*it == '.') {
      idx++;
      if (idx == 1) {
        // Found the first .
        num_header = (it - jws_token);
        payload = (it + 1);
      }
      if (idx == 2) {
        // Found the 2nd .
        num_payload = (it - payload);
        num_signature = num_jws_token - (it - jws_token) - 1;
        signature = it + 1;
      }
    } else if (!Base64Encode::IsValidBase64Char(*it)) {
      throw TokenFormatError("invalid base64 char.");
    }
  }

  if (idx != 2) {
    throw TokenFormatError("Invalid number of header sections.");
  }

  // Base64url decode the Encoded JOSE Header following the restriction that no
  // line breaks, whitespace, or other additional characters have been used.
  size_t num_dec_header = Base64Encode::DecodeBytesNeeded(num_header);
  str_ptr dec_header(new char[num_dec_header]);

  if (Base64Encode::DecodeUrl(header, num_header, dec_header.get(),
                              &num_dec_header) != 0) {
    // This cannot happen, as we have checked for valid characters already..
    throw std::logic_error("validated header block has invalid characters");
  }

  // Make sure we have a proper \0 termination
  dec_header.get()[num_dec_header] = 0;

  json_error_t error;
  json header_claims = json::parse(dec_header.get());

  /*
  if (!header_claims) {
    throw TokenFormatError(std::string("header contains invalid json, ") +=
  error.text);
  }
  */

  json payload_claims = ExtractPayload(payload, num_payload);

  VerifySignature(header_claims, header, num_header + num_payload + 1,
                  signature, num_signature, verifier);
  if (validator) {
    validator->IsValid(payload_claims);
  }

  return new JWT(header_claims, payload_claims);
}

json JWT::ExtractPayload(const char *payload, size_t num_payload) {
  size_t num_dec_payload = Base64Encode::DecodeBytesNeeded(num_payload);
  str_ptr dec_payload(new char[num_dec_payload]);

  if (Base64Encode::DecodeUrl(payload, num_payload, dec_payload.get(),
                              &num_dec_payload) != 0) {
    // This cannot happen, as we have checked for valid characters already..
    throw std::logic_error("validated block has base64 error in payload");
  }

  // Make sure we have a proper \0 termination
  dec_payload.get()[num_dec_payload] = 0;
  return json::parse(dec_payload.get());
}

bool JWT::VerifySignature(json header_claims_, const char *header,
                          size_t num_header_and_payload, const char *signature,
                          size_t num_signature, MessageValidator *verifier) {
  if (verifier == nullptr) {
    return true;
  }

  if (!header_claims_.count("alg")) {
    throw InvalidSignatureError("Missing alg header");
  }

  if (!verifier->Accepts(header_claims_["alg"].get<std::string>())) {
    throw InvalidSignatureError(
        std::string("Verifier does not accept alg header: ") +=
        header_claims_["alg"]);
  }

  str_ptr heapsig;
  char stacksig[MAX_SIGNATURE_LENGTH];
  char *dec_signature = stacksig;

  // But there might be a case where it is not going to be enough..
  size_t num_dec_signature = Base64Encode::DecodeBytesNeeded(num_signature);
  if (num_dec_signature > MAX_SIGNATURE_LENGTH) {
    heapsig = str_ptr(new char[num_dec_signature]);
    dec_signature = heapsig.get();
  }

  if (Base64Encode::DecodeUrl(signature, num_signature, dec_signature,
                              &num_dec_signature)) {
    // Shouldn't happen. At this point the token contains valid base64 chars.
    throw std::logic_error("validated block has base64 error in signature");
  }

  if (!verifier->Verify(
          header_claims_,
          reinterpret_cast<uint8_t *>(const_cast<char *>(header)),
          num_header_and_payload,
          reinterpret_cast<uint8_t *>(const_cast<char *>(dec_signature)),
          num_dec_signature)) {
    throw InvalidSignatureError("Unable to verify signature");
  }

  return true;
}
