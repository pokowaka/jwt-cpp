#ifndef VALIDATORS_DIGESTVALIDATOR_H
#define VALIDATORS_DIGESTVALIDATOR_H

#include <openssl/hmac.h>
#include <string>
#include "messagevalidator.h"

/**
 * Can sign & validate using an openssl digest function. Signing and Verification
 * are not thread safe functions.
 */
class DigestValidator : public MessageValidator {
public:
    explicit DigestValidator(const char *algorithm, const EVP_MD *md, const std::string &key);

    ~DigestValidator();

    bool VerifySignature(const uint8_t *header, size_t num_header,
                         const uint8_t *signature, unsigned int num_signature);

    bool Sign(const uint8_t *header, size_t num_header,
              uint8_t *signature, unsigned int *num_signature);

    inline unsigned int key_size() { return key_size_; }

    inline const char *algorithm() { return algorithm_; }

private:
    HMAC_CTX ctx_;
    unsigned int key_size_;
    const char *algorithm_;
};

class HS256Validator : public DigestValidator {
public:
    explicit HS256Validator(const std::string &key) : DigestValidator("HS256", EVP_sha256(), key) { }
};

class HS384Validator : public DigestValidator {
public:
    explicit HS384Validator(const std::string &key) : DigestValidator("HS384", EVP_sha384(), key) { }
};

class HS512Validator : public DigestValidator {
public:
    explicit HS512Validator(const std::string &key) : DigestValidator("HS512", EVP_sha512(), key) { }
};

#endif //VALIDATORS_DIGESTVALIDATOR_H
