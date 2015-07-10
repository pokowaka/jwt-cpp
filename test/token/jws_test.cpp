#include "token/jwsverifier.h"
#include <memory>
#include <string>
#include "validators/digestvalidator.h"
#include "gtest/gtest.h"

class BadValidator : public MessageValidator {
  bool VerifySignature(const uint8_t *header, size_t num_header,
      const uint8_t *signature, size_t num_signature) {
    return false;
  }

  // if signature == 0, or *num_signate is less than what is needed for a signature
  // the method should return false, and num_signature should contain the number
  // of bytes needed to place the signature in.
  bool Sign(const uint8_t *header, size_t num_header,
      uint8_t *signature, size_t *num_signature) {
    *num_signature = 8;
    return false;
  };
  const char *algorithm() const {
    return "BAD";
  };
};

TEST(jws_test, header_signature) {
  HS256Validator validator("secret");
  JwsVerifier jws(&validator);
  std::string header= "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
  std::string signature = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";

  EXPECT_EQ(true, jws.VerifySignature("HS256", header.c_str(), header.size(), signature.c_str(), signature.size()));
}

TEST(jws_test, multiple_algorithms) {
  HS256Validator hs256("secret");
  HS384Validator hs384("secret");
  HS512Validator hs512("secret");
  MessageValidator* validators[] { &hs256, &hs384, &hs512 };
  JwsVerifier jws(validators, 3);

  std::string header= "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
  std::string signature = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";

  EXPECT_EQ(true, jws.VerifySignature("HS256", header.c_str(), header.size(), signature.c_str(), signature.size()));
}


TEST(jws_test, can_sign) {
  HS256Validator validator("secret");
  JwsVerifier jws(&validator);
  std::string header= "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
  std::string expected = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
  char buffer[4096];
  size_t num_buffer = 4096;

  EXPECT_STREQ(expected.c_str(), jws.Sign("HS256", header.c_str(), header.size(), buffer, &num_buffer));
}

TEST(jws_test, bad_signer_will_fail) {
  BadValidator validator;
  JwsVerifier jws(&validator);
  std::string header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
  std::string expected = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
  char buffer[4096];
  size_t num_buffer = 4096;

  EXPECT_EQ(NULL, jws.Sign("BAD", header.c_str(), header.size(), buffer, &num_buffer));
}

TEST(jws_test, no_such_algorithm) {
  HS256Validator validator("secret");
  JwsVerifier jws(&validator);
  std::string header= "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
  std::string signature = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";

  EXPECT_EQ(false, jws.VerifySignature("HS512", header.c_str(), header.size(), signature.c_str(), signature.size()));
}

TEST(jws_test, sign_no_such_algorithm) {
  HS256Validator validator("secret");
  JwsVerifier jws(&validator);
  std::string header= "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
  char signature[4096];
  size_t num_signature = 4096;

  EXPECT_EQ(NULL, jws.Sign("HS512", header.c_str(), header.size(), signature, &num_signature));
}

TEST(jws_test, need_space_for_array) {
  HS256Validator validator("secret");
  JwsVerifier jws(&validator);
  std::string header= "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
  size_t num_signature = 4096;

  EXPECT_EQ(NULL, jws.Sign("HS256", header.c_str(), header.size(), NULL, &num_signature));
  EXPECT_EQ(44, num_signature); // 43 chars + \00
}

TEST(jws_test, bad_base_64_header) {
  HS256Validator validator("secret");
  JwsVerifier jws(&validator);
  std::string header= "eyJh b G c iOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
  std::string signature = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";

  EXPECT_EQ(false, jws.VerifySignature("HS256", header.c_str(), header.size(), signature.c_str(), signature.size()));
}

TEST(jws_test, bad_base_64_signature) {
  HS256Validator validator("secret");
  JwsVerifier jws(&validator);

  std::string header= "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
  std::string signature = "T J V A 95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";

  EXPECT_EQ(false, jws.VerifySignature("HS256", header.c_str(), header.size(), signature.c_str(), signature.size()));
}
