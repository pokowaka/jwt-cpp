#include "jwsverifier.h"
#include <stdint.h>
#include <jansson.h>
#include <memory>
#include "base64/base64.h"
#include "claimset.h"

JwsVerifier::JwsVerifier(MessageValidator **validators, size_t num_validators) {
    for (int i = 0; i < num_validators; i++) {
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
                                  const char *signature, size_t num_signature) {
    auto alg = validator_map_.find(algorithm);
    if (alg == validator_map_.end()) {
        return false;
    }

    size_t num_dec_signature = 1 + ((num_signature / 3) + (num_signature % 3 > 0)) * 4;
    std::unique_ptr<char> dec_signature(new char[num_dec_signature]);

    if (Base64Encode::DecodeUrl(signature, num_signature, dec_signature.get(), &num_dec_signature)) {
        return false;
    }

    return alg->second->VerifySignature((uint8_t *) header, num_header, (uint8_t *) dec_signature.get(),
                                        (unsigned int) num_dec_signature);
}
