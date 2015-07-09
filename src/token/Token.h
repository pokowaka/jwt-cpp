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
#ifndef SRC_TOKEN_TOKEN_H_
#define SRC_TOKEN_TOKEN_H_

#include <stddef.h>
#include <jansson.h>
#include <memory>
#include "validators/claimvalidator.h"
#include "validators/messagevalidator.h"
#include "token/jwsverifier.h"

/**
 * A Json web token..
 */
class Token {
 public:
    // returns a parsed token, or null if it is not a json webtoken.
    static Token* Parse(const char *jws_token, size_t num_jws_token);
    static Token* Parse(const char *jws_token, size_t num_jws_token,
        const JwsVerifier &verifier, const ClaimValidator &validator);
    ~Token();

    static char* Encode(json_t* payload, MessageValidator* validator);
    bool IsEncrypted();
    bool VerifySignature(const JwsVerifier &verifier);
    bool VerifyClaims(const ClaimValidator &claimValidator);

    inline json_t* header_claims() { return header_claims_; }
    json_t* payload_claims();

 private:
    Token(const char *header, const char *payload, const char *signature,
        size_t num_header, size_t num_payload, size_t num_signature, json_t* header_claims);

    const char *header_, *payload_, *signature_;
    size_t num_header_, num_payload_, num_signature_;
    bool invalid_payload_;
    json_t* header_claims_;
    json_t* payload_claims_;
};

#endif  // SRC_TOKEN_TOKEN_H_
