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
#include <jansson.h>
#include <string>
#include "base64/base64.h"
#include "util/allocators.h"


JWT::JWT(json_t *header_claims, json_t *payload_claims, bool issigned, bool valid)
    : header_(header_claims), payload_(payload_claims), signed_(issigned),
      valid_(valid) { }

JWT::~JWT() {
  json_decref(header_);
  json_decref(payload_);
}

char *JWT::Encode(MessageSigner *validator, json_t *payload, json_t *header) {
  json_ptr jose_header(json_object());
  if (!header) {
    header = jose_header.get();
  }

  // Set proper header flags.
  json_object_set(header, "typ", json_string("JWT"));
  json_object_set(header, "alg", json_string(validator->algorithm()));

  // Encode the header
  json_str str_header(json_dumps(header, JSON_COMPACT));
  size_t num_header = strlen(str_header.get());
  size_t num_enc_header = Base64Encode::EncodeBytesNeeded(num_header);
  str_ptr enc_header(new char[num_enc_header]);
  Base64Encode::EncodeUrl(str_header.get(), num_header, enc_header.get(), &num_enc_header);

  // Encode the payload
  json_str str_payload(json_dumps(payload, JSON_COMPACT));
  size_t num_payload = strlen(str_payload.get());
  size_t num_enc_payload = Base64Encode::EncodeBytesNeeded(num_payload);
  str_ptr enc_payload(new char[num_enc_payload]);
  Base64Encode::EncodeUrl(str_payload.get(), num_payload, enc_payload.get(), &num_enc_payload);

  // Now combine the header & payload (Note, that num_enc_payload & num_enc_header contain \0 char)
  size_t num_signed_area = num_enc_payload + num_enc_header;
  str_ptr str_signed_area(new char[num_signed_area]);

  snprintf(str_signed_area.get(), num_signed_area, "%s.%s", enc_header.get(), enc_payload.get());

  size_t num_signature = 0;
  size_t strlen_signed_area = num_signed_area - 1;  // We don't want to sign the null terminator!
  validator->Sign(reinterpret_cast<uint8_t *>(str_signed_area.get()),
                  strlen_signed_area, NULL, &num_signature);

  str_ptr str_signature(new char[num_signature]);
  if (!validator->Sign(reinterpret_cast<uint8_t *>(str_signed_area.get()),
                       strlen_signed_area, reinterpret_cast<uint8_t *> (str_signature.get()),
                       &num_signature)) {
    return nullptr;
  }

  size_t num_enc_signature = Base64Encode::EncodeBytesNeeded(num_signature);
  str_ptr enc_signature(new char[num_enc_signature]);
  Base64Encode::EncodeUrl(str_signature.get(), num_signature,
                          enc_signature.get(), &num_enc_signature);

  size_t num_token = num_signed_area + num_enc_signature + 1;
  str_ptr token(new char[num_token]);
  snprintf(token.get(), num_token, "%s.%s", str_signed_area.get(), enc_signature.get());

  return token.release();
}

JWT *JWT::Decode(std::string jwsToken, MessageValidator *verifier, ClaimValidator *validator) {
  return Decode(jwsToken.c_str(), jwsToken.size(), verifier, validator);
}

JWT *JWT::Decode(const char *jws_token, size_t num_jws_token, MessageValidator *verifier,
                 ClaimValidator *validator) {
  int idx = 0;
  const char *header = jws_token, *payload = jws_token, *signature = jws_token, *it = jws_token;
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
    throw TokenFormatError("More than two header sections.");
  }

  // Base64url decode the Encoded JOSE Header following the restriction that no line breaks,
  // whitespace, or other additional characters have been used.
  size_t num_dec_header = Base64Encode::DecodeBytesNeeded(num_header);
  str_ptr dec_header(new char[num_dec_header]);

  if (Base64Encode::DecodeUrl(header, num_header, dec_header.get(), &num_dec_header) != 0) {
    throw std::logic_error("validated header block has invalid characters");
  }

  // Make sure we have a proper \0 termination
  dec_header.get()[num_dec_header] = 0;

  json_error_t error;
  json_ptr header_claims(json_loads(dec_header.get(), JSON_REJECT_DUPLICATES, &error));

  if (!header_claims.get()) {
    throw TokenFormatError(std::string("header contains invalid json, ") += error.text);
  }

  json_ptr payload_claims(ExtractPayload(payload, num_payload));

  bool issigned = VerifySignature(header_claims.get(),
                                  header, num_header + num_payload + 1,
                                  signature, num_signature,
                                  verifier);
  bool isvalid = validator && validator->IsValid(payload_claims.get());

  return new JWT(header_claims.release(), payload_claims.release(), issigned, isvalid);
}

json_t *JWT::ExtractPayload(const char *payload, size_t num_payload) {
  size_t num_dec_payload = Base64Encode::DecodeBytesNeeded(num_payload);
  str_ptr dec_payload(new char[num_dec_payload]);

  if (Base64Encode::DecodeUrl(payload, num_payload, dec_payload.get(), &num_dec_payload) != 0) {
    throw std::logic_error("validated block has base64 error in payload");
  }

  // Make sure we have a proper \0 termination
  dec_payload.get()[num_dec_payload] = 0;
  json_error_t error;
  json_t *json = json_loads(dec_payload.get(), JSON_REJECT_DUPLICATES, &error);
  if (!json) {
    throw TokenFormatError(std::string("header contains invalid json, ") += error.text);
  }
  return json;
}

bool JWT::VerifySignature(json_t *header_claims_, const char *header,
                            size_t num_header_and_payload, const char *signature,
                            size_t num_signature, MessageValidator *verifier) {
  if (verifier == nullptr) {
    return false;
  }

  json_t *alg = json_object_get(header_claims_, "alg");
  if (!json_is_string(alg)) {
    return false;
  }

  if (!verifier->Accepts(json_string_value(alg))) {
    return false;
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

  if (Base64Encode::DecodeUrl(signature, num_signature, dec_signature, &num_dec_signature)) {
    throw std::logic_error("validated block has base64 error in signature");
  }

  return verifier->Verify(header_claims_,
                          reinterpret_cast<uint8_t *>(const_cast<char *>(header)),
                          num_header_and_payload,
                          reinterpret_cast<uint8_t *>(const_cast<char *>(dec_signature)),
                          num_dec_signature);
}
