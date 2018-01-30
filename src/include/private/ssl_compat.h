#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
// ssl < 1.1
class EvpMdCtx {
 public:
  EvpMdCtx() { EVP_MD_CTX_init(&ctx_); }

  ~EvpMdCtx() { EVP_MD_CTX_cleanup(&ctx_); }

  EVP_MD_CTX* get() { return &ctx_; }

 private:
  EVP_MD_CTX ctx_;
};

class HMacCtx {
 public:
  HMacCtx() { HMAC_CTX_init(&ctx_); }

  ~HMacCtx() { HMAC_CTX_cleanup(&ctx_); }

  HMAC_CTX* get() { return &ctx_; }

 private:
  HMAC_CTX ctx_;
};
#else
class EvpMdCtx {
 public:
  EvpMdCtx() { ctx_ = EVP_MD_CTX_new(); }

  ~EvpMdCtx() { EVP_MD_CTX_free(ctx_); }

  EVP_MD_CTX* get() { return ctx_; }

 private:
  EVP_MD_CTX* ctx_;
};

class HMacCtx {
 public:
  HMacCtx() { ctx_ = HMAC_CTX_new(); }

  ~HMacCtx() { HMAC_CTX_free(ctx_); }

  HMAC_CTX* get() { return ctx_; }

 private:
  HMAC_CTX* ctx_;
};
#endif


