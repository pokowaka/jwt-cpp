#ifndef TOKEN_JWSVERIFIER_H
#define TOKEN_JWSVERIFIER_H


#include <string.h>
#include <openssl/hmac.h>
#include <map>
#include <string>
#include "validators/messagevalidator.h"

class JwsVerifier {
 public:
    JwsVerifier() {}
    JwsVerifier(MessageValidator **validators, size_t num_validators);
    explicit JwsVerifier(MessageValidator* validator);
    bool VerifySignature(std::string algorithm, const char *header, size_t num_header,
                         const char *signature, size_t num_signature);
    bool RegisterValidator(MessageValidator *validator);

 private:
    std::map<std::string, MessageValidator *> validator_map_;
};


#endif //TOKEN_JWSVERIFIER_H
