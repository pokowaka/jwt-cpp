#include "digestvalidator.h"
#include <string>
#include <memory>

DigestValidator::DigestValidator(const char *algorithm,
                                 const EVP_MD *md, const std::string &key) {
    key_size_ = md->md_size;
    algorithm_ = algorithm;
    HMAC_CTX_init(&ctx_);
    HMAC_Init_ex(&ctx_, key.c_str(), key.size(), md, NULL);
}

DigestValidator::~DigestValidator() {
    HMAC_CTX_cleanup(&ctx_);
}

bool DigestValidator::VerifySignature(const uint8_t *header, size_t num_header,
                                      const uint8_t *signature, unsigned int num_signature) {
    // No need to calc the signature if it is going be the wrong size.
    if (num_signature != key_size_)
        return false;

    unsigned int num_local_signature = key_size_;
    std::unique_ptr<uint8_t> local_signature(new uint8_t[key_size_]);
    return Sign(header, num_header, local_signature.get(), &num_local_signature)
           && num_local_signature == key_size_
           && memcmp(local_signature.get(), signature, key_size_) == 0;
}

bool DigestValidator::Sign(const uint8_t *header, size_t num_header,
                           uint8_t *signature, unsigned int *num_signature) {
    HMAC_Init(&ctx_, 0, 0, 0); // We need to clean out any state..
    return HMAC_Update(&ctx_, header, num_header) && HMAC_Final(&ctx_, signature, num_signature);
}


