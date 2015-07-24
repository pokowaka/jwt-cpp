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
#include "private/jwe.h"
#include <string.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "private/base64.h"
#include "jwt/allocators.h"

inline bool Jwe::isSet(json_t *json, const char *key, const char *expected) {
    json_t *object = json_object_get(json, key);
    if (!object || !json_is_string(object)) {
        return false;
    }
    const char *value = json_string_value(object);
    return (strcmp(expected, value) == 0);
}

Jwe::Jwe(const char *private_key) {
    rsa_ = createRSA(private_key, false);
}

Jwe::~Jwe() {
    RSA_free(rsa_);
}

RSA *Jwe::createRSA(const char *key, bool public_key) {
    RSA *rsa = NULL;
    BIO *keybio = BIO_new_mem_buf(
        const_cast<void*>(reinterpret_cast<const void*>(key)), -1);
    if (keybio == NULL) {
        return 0;
    }
    if (public_key) {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    } else {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }

    BIO_set_close(keybio, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
    BIO_free(keybio);

    if (rsa == NULL) {
        char buffer[120];
        ERR_error_string(ERR_get_error(), buffer);
        fprintf(stderr, "OpenSSL error: %s", buffer);
        exit(0);
    }

    return rsa;
}

// c version of rubies: str[1 .. -2].gsub('\"', '"')
inline size_t shimBrokenRubyJWE(uint8_t *str) {
    char *p = reinterpret_cast<char*>(str);
    char *back = p;
    size_t replaced = 2;   // Removal of front and end "
    while (*p != 0) {
        if (*p++ == '\\' && *p == '"') {
            *(back-1) = '"';
            replaced++;
        } else {
            *back++ = *p;
        }
    }
    *(back-2) = 0;
    return replaced;
}


bool Jwe::Decrypt(json_t *jwe_header, uint8_t *payload, size_t num_payload,
                  uint8_t *signature, size_t num_signature,
                  uint8_t **decrypted, size_t *num_decrypted) const {
    *decrypted = nullptr;
    *num_decrypted = 0;

    // Validate the headers..
    if (!isSet(jwe_header, "alg", "RSA1_5") || !isSet(jwe_header, "enc", "A256CBC")) {
        return false;
    }

    json_t *iv_part = json_object_get(jwe_header, "iv");
    if (iv_part == NULL) {
        return false;
    }

    // First we extract the IV and decode it.
    const char *base64_iv = json_string_value(iv_part);
    size_t num_base64_iv = strlen(base64_iv);
    size_t num_iv = Base64Encode::DecodeBytesNeeded(num_base64_iv);

    // Oh oh, this will never work!
    if (num_iv > MAX_IV_SIZE) {
        return false;
    }

    char iv[MAX_IV_SIZE];
    Base64Encode::DecodeUrl(base64_iv, num_base64_iv, iv, &num_iv);


    // Lets decrypt the cipher key.
    std::unique_ptr<uint8_t[]> cipher_key(new uint8_t[RSA_size(rsa_)]);
    int num_cipher_key = RSA_private_decrypt(num_payload,
        payload, cipher_key.get(), rsa_, RSA_PKCS1_PADDING);
    if (num_cipher_key < 0) {
        return false;
    }

    // ok great, we now have the aes key
    // Well, obviously the decrypted data <= num_cipher_buf
    int num_cipher_buf = num_signature, num_cipher_buf2 = 0;
    std::unique_ptr<uint8_t[]> cipher_buf(new uint8_t[num_cipher_buf]);

    // Actually decrypt the things..
    EVP_CIPHER_CTX ctx;
    if (!EVP_CipherInit(&ctx, EVP_aes_256_cbc(), cipher_key.get(), (const uint8_t*) iv, false)) {
        return false;
    }
    if (!EVP_CipherUpdate(&ctx, cipher_buf.get() , &num_cipher_buf, signature, num_signature)) {
        return false;
    }
    if (!EVP_CipherFinal(&ctx, cipher_buf.get()+num_cipher_buf, &num_cipher_buf2)) {
     return false;
    }

    // Fix up a broken ruby implementation
    if (cipher_buf.get()[0] == '"') {
        // Well. guess what.. turns out that jwe-0.1.x ruby version (used by lookout)
        // has a broken decryption.. So we need to fix that up..
        cipher_buf.get()[num_cipher_buf + num_cipher_buf2] = 0;
        int rem = shimBrokenRubyJWE(cipher_buf.get());
        num_cipher_buf -= rem;
    }

    // And return the results...
    *decrypted = cipher_buf.release();
    *num_decrypted = num_cipher_buf + num_cipher_buf2;

    return true;
}
