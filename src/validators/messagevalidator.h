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
#ifndef SRC_VALIDATORS_MESSAGEVALIDATOR_H_
#define SRC_VALIDATORS_MESSAGEVALIDATOR_H_

#include <stdint.h>

/**
 * A MessageValidator can validate and sign a header.
 */
class MessageValidator {
 public:
  /**
   * Verifies that the given signature belongs with the given header
   */
  virtual bool VerifySignature(const uint8_t *header, size_t num_header,
                               const uint8_t *signature, size_t num_signature) = 0;

  // if signature == 0, or *num_signate is less than what is needed for a signature
  // the method should return false, and num_signature should contain the number
  // of bytes needed to place the signature in.
  virtual bool Sign(const uint8_t *header, size_t num_header,
                    uint8_t *signature, size_t *num_signature) = 0;
  virtual const char *algorithm() const = 0;
};

#endif  // SRC_VALIDATORS_MESSAGEVALIDATOR_H_
