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
#include "jwt/rsavalidator.h"
#include "private/ssl_compat.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <regex> // NOLINT(*)
#include <sstream>
#include <string>
#include <utility>

RSAValidator::RSAValidator(std::string algorithm, const EVP_MD *md,
                           const std::string &key)
    : algorithm_(std::move(algorithm)), private_key_(nullptr),
      public_key_(nullptr), md_(md) {
  public_key_ = LoadKey(key.c_str(), true);
}

RSAValidator::RSAValidator(const std::string &algorithm, const EVP_MD *md,
                           const std::string &key,
                           const std::string &private_key)
    : RSAValidator(algorithm, md, key) {
  private_key_ = LoadKey(private_key.c_str(), false);
}

RSAValidator::~RSAValidator() {
  EVP_PKEY_free(public_key_);
  EVP_PKEY_free(private_key_);
}

bool RSAValidator::Verify(const json & /*jsonHeader*/, const uint8_t *header,
                          size_t num_header, const uint8_t *signature,
                          size_t num_signature) const {
  EvpMdCtx ctx;
  EVP_MD_CTX *evp_md_ctx = ctx.get();
  EVP_MD_CTX_init(evp_md_ctx);
  EVP_VerifyInit_ex(evp_md_ctx, md_, nullptr);
  bool valid =
      EVP_VerifyUpdate(evp_md_ctx, header, num_header) == 1 &&
      EVP_VerifyFinal(evp_md_ctx, signature, num_signature, public_key_) == 1;
  return valid;
}

bool RSAValidator::Sign(const uint8_t *header, size_t num_header,
                        uint8_t *signature, size_t *num_signature) const {
  size_t needed = 0;
  bool success = false;

  EvpMdCtx ctx;
  EVP_MD_CTX *evp_md_ctx = ctx.get();
  EVP_MD_CTX_init(evp_md_ctx);
  EVP_DigestSignInit(evp_md_ctx, nullptr, md_, nullptr, private_key_);
  if (EVP_DigestSignUpdate(evp_md_ctx, header, num_header) != 1) {
    goto Error;
  }

  // Figure out how many bytes we need
  if (EVP_DigestSignFinal(evp_md_ctx, nullptr, &needed) != 1) {
    goto Error;
  }

  // We need more bytes please!
  if (signature == nullptr || *num_signature < needed) {
    *num_signature = needed;
    goto Error;
  }

  success = EVP_DigestSignFinal(evp_md_ctx, signature, num_signature) == 1;
Error:
  return success;
}

EVP_PKEY *RSAValidator::LoadKey(const char *key, bool public_key) {
  EVP_PKEY *evp_pkey = nullptr;
  BIO *keybio =
      (key == nullptr) || (*key == 0)
          ? nullptr
          : BIO_new_mem_buf(
                const_cast<void *>(reinterpret_cast<const void *>(key)), -1);
  if (keybio == nullptr) {
    return nullptr;
  }

  if (public_key) {
    evp_pkey = PEM_read_bio_PUBKEY(keybio, &evp_pkey, nullptr, nullptr);
  } else {
    evp_pkey = PEM_read_bio_PrivateKey(keybio, &evp_pkey, nullptr, nullptr);
  }

  BIO_free(keybio);

  if (evp_pkey == nullptr) {
    char buffer[120];
    ERR_error_string(ERR_get_error(), buffer);
    throw InvalidValidatorError(std::string("Unable to construct ") +
                                (public_key ? "public key" : "private key") +
                                " due to: " + std::string(buffer));
  }

  return evp_pkey;
}

std::string RSAValidator::toJson() const {
  std::ostringstream msg;
  char *key;
  std::regex newline("\n");

  msg << "{ \"" << algorithm() << "\" : { ";

  if (public_key_ != nullptr) {
    BIO *out = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(out, public_key_);
    uint64_t len = BIO_get_mem_data(out, &key);
    std::string pubkey = std::string(key, len);
    msg << R"("public" : ")" << std::regex_replace(pubkey, newline, "\\n")
        << "\"";
    BIO_free(out);

    if (private_key_ != nullptr) {
      msg << ", ";
      BIO *out = BIO_new(BIO_s_mem());
      PEM_write_bio_PrivateKey(out, private_key_, nullptr, nullptr, 0, nullptr,
                               nullptr);
      uint64_t len = BIO_get_mem_data(out, &key);
      std::string privkey = std::string(key, len);
      msg << R"("private" : ")" << std::regex_replace(privkey, newline, "\\n")
          << "\"";
      BIO_free(out);
    }
  }

  msg << "} }";
  return msg.str();
}
