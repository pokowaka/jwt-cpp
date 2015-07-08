#include <base64/base64.h>
#include "Token/Token.h"

Token *Token::parse(const char *jws_token, size_t num_jws_token) {
    int idx = 0;
    const char *header = jws_token, *payload = jws_token, *signature = jws_token;
    size_t num_header, num_payload, num_signature;

    for (; signature < (jws_token + num_jws_token) && idx < 2; signature++) {
        if (*signature == '.') {
            idx++;
            if (idx == 1) {
                // Found the first .
                num_header = (signature - jws_token);
                payload = (signature + 1);
            }
            if (idx == 2) {
                // Found the 2nd .
                num_payload = (signature - payload);
                num_signature = num_jws_token - (signature - jws_token) - 1;
            }
        }
    }

    if (idx != 2)
        return nullptr;

    // Base64url decode the Encoded JOSE Header following the restriction that no line breaks,
    // whitespace, or other additional characters have been used.
    size_t num_dec_header = 1 + ((num_header / 3) + (num_header % 3 > 0)) * 4;
    std::unique_ptr<char> dec_header(new char[num_dec_header]);

    if (Base64Encode::DecodeUrl(header, num_header, dec_header.get(), &num_dec_header) != 0) {
        return nullptr;
    }

    // Make sure we have a proper \0 termination
    dec_header.get()[num_dec_header] = 0;
    std::unique_ptr<ClaimSet> header_claims(ClaimSet::parseJson(dec_header.get()));
    if (!header_claims.get()) {
        return nullptr;
    }

    return new Token(header, payload, signature, num_header, num_payload, num_signature, header_claims.release());
}

Token::Token(const char *header, const char *payload, const char *signature, size_t num_header, size_t num_payload,
             size_t num_signature, ClaimSet *header_claims) :
        header_(header), payload_(payload), signature_(signature), num_header_(num_header), num_payload_(num_payload),
        num_signature_(num_signature), invalid_payload_(false), header_claims_(header_claims),
        payload_claims_(nullptr) {
}

bool Token::IsEncrypted() {
    return header_claims_->HasKey("enc");
}

ClaimSet *Token::payload_claims() {
    if (payload_claims_.get() != nullptr) {
        return payload_claims_.get();
    }

    // You need to decrypt the claims first..
    if (IsEncrypted() || invalid_payload_)
        return nullptr;

    size_t num_dec_payload = 1 + ((num_payload_ / 3) + (num_payload_ % 3 > 0)) * 4;
    std::unique_ptr<char> dec_payload(new char[num_dec_payload]);

    if (Base64Encode::DecodeUrl(payload_, num_payload_, dec_payload.get(), &num_dec_payload) != 0) {
        return nullptr;
    }

    // Make sure we have a proper \0 termination
    dec_payload.get()[num_dec_payload] = 0;
    payload_claims_ = std::unique_ptr<ClaimSet>(ClaimSet::parseJson(dec_payload.get()));
    invalid_payload_ = payload_claims_.get() == nullptr;
    return payload_claims_.get();
}

bool Token::VerifySignature(JwsVerifier &verifier) {
    return !IsEncrypted() &&
           verifier.VerifySignature(header_claims_->Get("alg"),
                                    header_, num_payload_ + num_header_ + 1,
                                    signature_, num_signature_);

}
