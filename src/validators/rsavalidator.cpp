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
#include <openssl/err.h>
#include <openssl/pem.h>
#include <string>
#include "validators/rsavalidator.h"

RSAValidator::RSAValidator(const char *algorithm, const EVP_MD *md, const std::string &key)
  : algorithm_(algorithm), private_key_(NULL), public_key_(NULL), md_(md) {
    public_key_ = LoadKey(key.c_str(), true);
  }

RSAValidator::RSAValidator(const char *algorithm, const EVP_MD *md, const std::string &key,
    const std::string &private_key) : RSAValidator(algorithm, md, key) {
  private_key_ = LoadKey(private_key.c_str(), false);
}

RSAValidator::~RSAValidator() {
  EVP_PKEY_free(public_key_);
  EVP_PKEY_free(private_key_);
}

bool RSAValidator::VerifySignature(const uint8_t *header,
    size_t num_header, const uint8_t *signature, size_t num_signature) {

  EVP_MD_CTX evp_md_ctx;
  EVP_MD_CTX_init(&evp_md_ctx);
  EVP_VerifyInit_ex(&evp_md_ctx, md_, NULL);
  bool valid = EVP_VerifyUpdate(&evp_md_ctx, header, num_header) == 1 &&
    EVP_VerifyFinal(&evp_md_ctx, signature, num_signature, public_key_) == 1;
  EVP_MD_CTX_cleanup(&evp_md_ctx);
  return valid;
}

bool RSAValidator::Sign(const uint8_t *header, size_t num_header,
    uint8_t *signature, size_t *num_signature) {
  size_t needed = 0;

  EVP_MD_CTX evp_md_ctx;
  EVP_MD_CTX_init(&evp_md_ctx);
  EVP_DigestInit_ex(&evp_md_ctx, md_, NULL);

  if (EVP_DigestSignUpdate(&evp_md_ctx, header, num_header) != 1) {
    return false;
  }

  // Figure out how many bytes we need
  if (EVP_DigestSignFinal(&evp_md_ctx, NULL, &needed) != 1) {
    return false;
  }

  // We need more bytes please!
  if (signature == NULL || *num_signature < needed) {
    *num_signature = needed;
    return false;
  }

  bool success = EVP_DigestSignFinal(&evp_md_ctx, signature, num_signature) == 1;
  EVP_MD_CTX_cleanup(&evp_md_ctx);
  return success;
}

EVP_PKEY *RSAValidator::LoadKey(const char *key, bool public_key) {
  EVP_PKEY *evp_pkey = NULL;
  BIO *keybio = BIO_new_mem_buf(
      const_cast<void*>(reinterpret_cast<const void *>(key)), -1);
  if (keybio == NULL) {
    return NULL;
  }

  if (public_key) {
    evp_pkey = PEM_read_bio_PUBKEY(keybio, &evp_pkey, NULL, NULL);
  } else {
    evp_pkey = PEM_read_bio_PrivateKey(keybio, &evp_pkey, NULL, NULL);
  }

  BIO_set_close(keybio, BIO_NOCLOSE);
  BIO_free(keybio);

  if (evp_pkey == NULL) {
    char buffer[120];
    ERR_error_string(ERR_get_error(), buffer);
    fprintf(stderr, "OpenSSL error: %s", buffer);
    exit(0);
  }

  return evp_pkey;
}
