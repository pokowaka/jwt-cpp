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
#include "token/token.h"
#include <base64/base64.h>
#include "util/allocators.h"

Token::~Token() {
  json_decref(header_claims_);
  json_decref(payload_claims_);
}

char* Token::Encode(json_t* payload, MessageValidator* validator) {
  unique_json_ptr jose_header(json_pack("{ss, ss}", "alg", validator->algorithm(), "typ", "JWT"));

  // Encode the header
  unique_json_str str_header(json_dumps(jose_header.get(), JSON_COMPACT));
  size_t num_header = strlen(str_header.get());
  size_t num_enc_header = Base64Encode::EncodeBytesNeeded(num_header);
  str_ptr enc_header(new char[num_enc_header]);
  Base64Encode::EncodeUrl(str_header.get(), num_header, enc_header.get(), &num_enc_header);

  // Encode the payload
  unique_json_str str_payload(json_dumps(payload, JSON_COMPACT));
  size_t num_payload = strlen(str_payload.get());
  size_t num_enc_payload = Base64Encode::EncodeBytesNeeded(num_payload);
  str_ptr enc_payload(new char[num_enc_payload]);
  Base64Encode::EncodeUrl(str_payload.get(), num_payload, enc_payload.get(), &num_enc_payload);

  // Now combine the header & payload (Note, that num_enc_payload & num_enc_header contain \0 char)
  size_t num_signed_area  = num_enc_payload + num_enc_header;
  str_ptr str_signed_area(new char[num_signed_area]);

  snprintf(str_signed_area.get(), num_signed_area, "%s.%s", enc_header.get(), enc_payload.get());

  size_t num_signature = 0;
  size_t strlen_signed_area = num_signed_area - 1;  // We don't want to sign the null terminator!
  validator->Sign(reinterpret_cast<uint8_t*>(str_signed_area.get()),
      strlen_signed_area, NULL, &num_signature);

  str_ptr str_signature(new char[num_signature]);
  if (!validator->Sign(reinterpret_cast<uint8_t*>(str_signed_area.get()),
        strlen_signed_area, reinterpret_cast<uint8_t*> (str_signature.get()),
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

bool Token::Decrypt(Jwe* decrypter) {
  if (decrypted_.get() != nullptr)
    return true;

  uint8_t* decrypted;

  size_t num_dec_payload = Base64Encode::DecodeBytesNeeded(num_payload_);
  str_ptr dec_payload(new char[num_dec_payload]);
  if (Base64Encode::DecodeUrl(payload_, num_payload_, dec_payload.get(), &num_dec_payload) != 0) {
    return nullptr;
  }


  size_t num_dec_signature  = Base64Encode::DecodeBytesNeeded(num_signature_);
  str_ptr dec_signature(new char[num_dec_signature]);
  if (Base64Encode::DecodeUrl(signature_, num_signature_, dec_signature.get(),
        &num_dec_signature) != 0) {
    return nullptr;
  }


  if (decrypter->Decrypt(header_claims_, reinterpret_cast<uint8_t*>(dec_payload.get()),
        num_dec_payload, reinterpret_cast<uint8_t*>(dec_signature.get()), num_dec_signature,
        &decrypted, &num_decrypted_)) {
    decrypted_.reset(decrypted);
    return true;
  }
  return false;
}

bool Token::VerifyClaims(ClaimValidator *claimValidator) {
  return claimValidator->IsValid(payload_claims());
}

Token *Token::Parse(const char *jws_token, size_t num_jws_token, JwsVerifier *verifier,
                    ClaimValidator *validator) {
  std::unique_ptr<Token> token(Token::Parse(jws_token, num_jws_token));
  if (!token.get() || !token->VerifySignature(verifier) || !token->VerifyClaims(validator))
    return nullptr;

  return token.release();
}

Token *Token::Parse(const char *jws_token, size_t num_jws_token) {
  int idx = 0;
  const char *header = jws_token, *payload = jws_token, *signature = jws_token;
  size_t num_header = 0, num_payload = 0, num_signature = 0;

  for (; signature < (jws_token + num_jws_token) && idx < 2; signature++) {
    if (*signature == '.') {
      idx++;
      if (idx == 1) {
        // Found the first .
        num_header = (signature - jws_token);
        payload = (signature + 1);
      }
      if (idx == 2) {
        // Found the 2nd .
        num_payload = (signature - payload);
        num_signature = num_jws_token - (signature - jws_token) - 1;
      }
    }
  }

  if (idx != 2)
    return nullptr;

  // Base64url decode the Encoded JOSE Header following the restriction that no line breaks,
  // whitespace, or other additional characters have been used.
  size_t num_dec_header = Base64Encode::DecodeBytesNeeded(num_header);
  str_ptr dec_header(new char[num_dec_header]);

  if (Base64Encode::DecodeUrl(header, num_header, dec_header.get(), &num_dec_header) != 0) {
    return nullptr;
  }

  // Make sure we have a proper \0 termination
  dec_header.get()[num_dec_header] = 0;

  json_error_t error;
  json_t *header_claims = json_loads(dec_header.get(), JSON_REJECT_DUPLICATES, &error);

  if (!header_claims) {
    return nullptr;
  }

  return new Token(header, payload, signature, num_header, num_payload,
      num_signature, header_claims);
}

Token::Token(const char *header, const char *payload, const char *signature,
    size_t num_header, size_t num_payload,
    size_t num_signature, json_t *header_claims) :
  header_(header), payload_(payload), signature_(signature), num_header_(num_header),
  num_payload_(num_payload), num_signature_(num_signature), invalid_payload_(false),
  header_claims_(header_claims), payload_claims_(nullptr) {
  }

bool Token::IsEncrypted() {
  return json_object_get(header_claims_, "enc") != NULL;
}

json_t *Token::payload_claims() {
  if (payload_claims_ != nullptr) {
    return payload_claims_;
  }

  // You need to decrypt the claims first..
  if (IsEncrypted() || invalid_payload_)
    return nullptr;

  size_t num_dec_payload = Base64Encode::DecodeBytesNeeded(num_payload_);
  str_ptr dec_payload(new char[num_dec_payload]);

  if (Base64Encode::DecodeUrl(payload_, num_payload_, dec_payload.get(), &num_dec_payload) != 0) {
    return nullptr;
  }

  // Make sure we have a proper \0 termination
  dec_payload.get()[num_dec_payload] = 0;
  json_error_t error;
  payload_claims_ = json_loads(dec_payload.get(), JSON_REJECT_DUPLICATES, &error);
  invalid_payload_ = payload_claims_ == nullptr;
  return payload_claims_;
}

bool Token::VerifySignature(JwsVerifier *verifier) {
  json_t *alg = json_object_get(header_claims_, "alg");
  return alg != NULL && !IsEncrypted() &&
    verifier->VerifySignature(json_string_value(alg),
        header_, num_payload_ + num_header_ + 1,
        signature_, num_signature_);
}
