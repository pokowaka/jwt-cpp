#include "validators/nonevalidator.h"
#include <string.h>

bool NoneValidator::VerifySignature(const uint8_t *header, size_t cHeader,
                                    const uint8_t *signature, unsigned int cSignature) {
  return cSignature == 0;
}
bool NoneValidator::Sign(const uint8_t *header, size_t cHeader,
                         uint8_t *signature, unsigned int *cSignature) {
  memset(signature, 0, *cSignature);
  *cSignature = 0;
  return true;
}

