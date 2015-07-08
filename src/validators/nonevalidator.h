#ifndef VALIDATORS_NONEVALIDATOR_H_
#define VALIDATORS_NONEVALIDATOR_H_

#include <stdint.h>
#include <stddef.h>
#include "messagevalidator.h"


/**
 * A validator that really doesn't do any validation at all.
 */
class NoneValidator : public MessageValidator {
public:
    bool VerifySignature(const uint8_t *header, size_t cHeader,
                         const uint8_t *signature, unsigned int cSignature);

    bool Sign(const uint8_t *header, size_t cHeader,
              uint8_t *signature, unsigned int *cSignature);

    const char *algorithm() { return "none"; };
};

#endif  // VALIDATORS_NONEVALIDATOR_H_
