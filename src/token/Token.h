#ifndef TOKEN_TOKEN_H
#define TOKEN_TOKEN_H

#include <stddef.h>
#include <memory>
#include "token/claimset.h"
#include "token/jwsverifier.h"

/**
 * A Json web token..
 */
class Token {
public:
    // returns a parsed token, or null if it is not a json webtoken.
    static Token* parse(const char *jws_token, size_t num_jws_token);

    bool IsEncrypted();
    bool VerifySignature(JwsVerifier &verifier);
    inline ClaimSet* header_claims() { return header_claims_.get(); }
    ClaimSet* payload_claims();

private:
    Token(const char *header, const char *payload, const char *signature,
          size_t num_header, size_t num_payload, size_t num_signature, ClaimSet* header_claims);

    const char *header_, *payload_, *signature_;
    size_t num_header_, num_payload_, num_signature_;
    bool invalid_payload_;
    std::unique_ptr<ClaimSet> header_claims_;
    std::unique_ptr<ClaimSet> payload_claims_;
};

#endif //TOKEN_TOKEN_H
