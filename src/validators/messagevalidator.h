#ifndef VALIDATORS_MESSAGEVALIDATOR_H_
#define VALIDATORS_MESSAGEVALIDATOR_H_

#include <stdint.h>

class MessageValidator {
public:
    virtual bool VerifySignature(const uint8_t *header, size_t num_header,
                                 const uint8_t *signature, unsigned int num_signature) = 0;

    virtual bool Sign(const uint8_t *header, size_t num_header,
                      uint8_t *signature, unsigned int *num_signature) = 0;

    virtual const char *algorithm() = 0;
};

#endif  // VALIDATORS_MESSAGEVALIDATOR_H_
