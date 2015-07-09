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
#ifndef SRC_TOKEN_JWSVERIFIER_H_
#define SRC_TOKEN_JWSVERIFIER_H_


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
                         const char *signature, size_t num_signature) const;
    char* Sign(std::string algorithm, const char *header, size_t num_header,
                         char *signature, size_t *num_signature) const;
    bool RegisterValidator(MessageValidator *validator);

 private:
    std::map<std::string, MessageValidator *> validator_map_;
};

#endif  // SRC_TOKEN_JWSVERIFIER_H_
