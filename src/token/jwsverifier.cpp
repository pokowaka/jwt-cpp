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
#include "token/jwsverifier.h"
#include <stdint.h>
#include <utility>
#include <string>
#include "util/allocators.h"
#include "base64/base64.h"

JwsVerifier::JwsVerifier(MessageValidator **validators, size_t num_validators) {
  for (size_t i = 0; i < num_validators; i++) {
    RegisterValidator(validators[i]);
  }
}

JwsVerifier::JwsVerifier(MessageValidator *validator) {
  RegisterValidator(validator);
}

bool JwsVerifier::RegisterValidator(MessageValidator *validator) {
  return validator_map_.insert(
      std::pair<std::string, MessageValidator *>(validator->algorithm(), validator)).second;
}

bool JwsVerifier::VerifySignature(std::string algorithm, const char *header, size_t num_header,
    const char *signature, size_t num_signature) const {
  auto alg = validator_map_.find(algorithm);
  if (alg == validator_map_.end()) {
    return false;
  }

  size_t num_dec_signature = Base64Encode::DecodeBytesNeeded(num_signature);
  char dec_signature[MAX_SIGNATURE_LENGTH];

  if (num_dec_signature > MAX_SIGNATURE_LENGTH) {
    return false;
  }

  if (Base64Encode::DecodeUrl(signature, num_signature, dec_signature, &num_dec_signature)) {
    return false;
  }

  return alg->second->VerifySignature(reinterpret_cast<const uint8_t*>(header),
      num_header, reinterpret_cast<const uint8_t*>(dec_signature),
      static_cast<unsigned int>(num_dec_signature));
}


char* JwsVerifier::Sign(std::string algorithm, const char *header, size_t num_header,
    char *signature, size_t *num_signature) const {
  auto alg = validator_map_.find(algorithm);
  if (alg == validator_map_.end()) {
    return nullptr;
  }
  MessageValidator* validator = alg->second;

  // Calculate size needed to store the signature..
  size_t num_raw_signature = 0;
  validator->Sign(reinterpret_cast<const uint8_t*>(header), num_header, NULL, &num_raw_signature);

  size_t needed = Base64Encode::EncodeBytesNeeded(num_raw_signature);
  // We have to little, set the needed size.
  if (signature == NULL || *num_signature < needed) {
    *num_signature = needed;
    return nullptr;
  }

  // The maximum length the raw signature can be after base64 encoding this result
  std::unique_ptr<uint8_t[]> raw_signature(new uint8_t[num_raw_signature]);

  if (!validator->Sign(reinterpret_cast<const uint8_t*>(header),
        num_header, (raw_signature.get()), &num_raw_signature)) {
    return nullptr;
  }

  // num_signature >= needed so the buffer is big enough
  Base64Encode::EncodeUrl(reinterpret_cast<char*>(raw_signature.get()), num_raw_signature, signature, *num_signature);
  return signature;
}

