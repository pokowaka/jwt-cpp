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


#define SIGNATURE_BUFFER 4096

class JwsVerifierTest : public ::testing::Test {
 public:
  JwsVerifierTest() : Test(), hs256_("secret"), jws_(&hs256_) {
    header_ = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
    signature_ = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
  }

 protected:
  // virtual void SetUp() { }
  // virtual void TearDown( {}
  std::string header_;
  std::string signature_;
  char buffer_[SIGNATURE_BUFFER];
  size_t num_buffer_ = SIGNATURE_BUFFER;
  HS256Validator hs256_;
  JwsVerifier jws_;
};


TEST_F(JwsVerifierTest, header_is_signed) {
  EXPECT_EQ(true,
      jws_.VerifySignature("HS256",
        header_.c_str(), header_.size(), signature_.c_str(), signature_.size()));
}

TEST_F(JwsVerifierTest, header_is_signed_multiple_validotors) {
  HS256Validator hs256("secret");
  HS384Validator hs384("secret");
  HS512Validator hs512("secret");
  MessageValidator* validators[] { &hs256, &hs384, &hs512 };
  JwsVerifier jws(validators, 3);

  EXPECT_EQ(true,
      jws.VerifySignature("HS256",
        header_.c_str(), header_.size(), signature_.c_str(), signature_.size()));
}


TEST_F(JwsVerifierTest, can_sign_a_header) {
  EXPECT_STREQ(signature_.c_str(),
      jws_.Sign("HS256", header_.c_str(), header_.size(), buffer_, &num_buffer_));
}

TEST_F(JwsVerifierTest, bad_validator_cannot_sign_a_header) {
  BadValidator validator;
  JwsVerifier jws(&validator);

  EXPECT_STREQ(NULL,
      jws.Sign("BAD", header_.c_str(), header_.size(), buffer_, &num_buffer_));
}

TEST_F(JwsVerifierTest, no_such_algorithm) {
  EXPECT_EQ(false,
      jws_.VerifySignature("HS512",
        header_.c_str(), header_.size(), signature_.c_str(), signature_.size()));
}

TEST_F(JwsVerifierTest, sign_no_such_algorithm) {
  EXPECT_EQ(NULL,
      jws_.Sign("HS512",
        header_.c_str(), header_.size(), buffer_, &num_buffer_));
}

TEST_F(JwsVerifierTest, need_space_for_array) {
  size_t num_signature = 0;

  EXPECT_EQ(NULL, jws_.Sign("HS256", header_.c_str(), header_.size(), NULL, &num_signature));
  EXPECT_EQ(44, num_signature); // 43 chars + \00
}

TEST_F(JwsVerifierTest, bad_base_64_header) {
  header_ = "eyJh b G c iOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";

  EXPECT_EQ(false,
      jws_.VerifySignature("HS256",
        header_.c_str(), header_.size(), signature_.c_str(), signature_.size()));
}

TEST_F(JwsVerifierTest, bad_base_64_signature) {
  signature_ = "T J V A 95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";

  EXPECT_EQ(false,
      jws_.VerifySignature("HS256",
        header_.c_str(), header_.size(), signature_.c_str(), signature_.size()));
}
