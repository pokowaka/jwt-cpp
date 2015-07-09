#include "token/jwsverifier.h"
#include <memory>
#include <string>
#include "validators/digestvalidator.h"
#include "gtest/gtest.h"

TEST(jws_test, header_signature) {
  HS256Validator validator("secret");
  JwsVerifier jws(&validator);
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

TEST(jws_test, no_such_algorithm) {
  HS256Validator validator("secret");
  JwsVerifier jws(&validator);
  std::string header= "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
  std::string signature = "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";

  EXPECT_EQ(false, jws.VerifySignature("HS512", header.c_str(), header.size(), signature.c_str(), signature.size()));
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
