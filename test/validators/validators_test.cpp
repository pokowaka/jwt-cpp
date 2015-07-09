#include "validators/digestvalidator.h"
#include "validators/nonevalidator.h"
#include "gtest/gtest.h"
#include <memory>
#include <string>
#include <array>

// Test for the various validators.

std::array<const EVP_MD *, 3> hmacs = {{EVP_sha256(), EVP_sha384(), EVP_sha512()}};
std::array<const char *, 3> names = {{"HS256", "HS384", "HS512"}};

TEST(hmacvalidator_test, unsigned_fails) {
    std::string message = "Hello World!";
    for (size_t i = 0; i < hmacs.size(); i++) {
        DigestValidator validator(names[i], hmacs[i], "foobar");
        size_t len = validator.key_size();
        std::unique_ptr<uint8_t[]> pSignature(new uint8_t[len]);
        memset(pSignature.get(), 0, len);
        EXPECT_EQ(false, validator.VerifySignature((uint8_t *) message.c_str(), message.size(), pSignature.get(), len));
    }
}

TEST(hmacvalidator_test, signing_succeeds) {
    std::string message = "Hello World!";
    for (size_t i = 0; i < hmacs.size(); i++) {
        DigestValidator validator(names[i], hmacs[i], "foobar");
        size_t len = validator.key_size();
        std::unique_ptr<uint8_t[]> pSignature(new uint8_t[len]);
        EXPECT_EQ(true, validator.Sign((uint8_t *) message.c_str(), message.size(), pSignature.get(), &len));
        EXPECT_EQ(true, validator.VerifySignature((uint8_t *) message.c_str(), message.size(), pSignature.get(), len));
    }
}

TEST(hmacvalidator_test, signing_on_substr) {
    std::string message = "Hello World!";
    for (size_t i = 0; i < hmacs.size(); i++) {
        DigestValidator validator(names[i], hmacs[i], "foobar");
        size_t len = validator.key_size();
        std::unique_ptr<uint8_t[]> pSignature(new uint8_t[len]);
        EXPECT_EQ(true, validator.Sign((uint8_t *) message.c_str(), 6, pSignature.get(), &len));
        EXPECT_EQ(true, validator.VerifySignature((uint8_t *) message.c_str(), 6, pSignature.get(), len));
    }
}


TEST(hmacvalidator_test, signing_does_not_change_length) {
    std::string message = "Hello World!";
    for (size_t i = 0; i < hmacs.size(); i++) {
        DigestValidator validator(names[i], hmacs[i], "foobar");
        size_t len = validator.key_size();
        std::unique_ptr<uint8_t[]> pSignature(new uint8_t[len]);
        EXPECT_EQ(true, validator.Sign((uint8_t *) message.c_str(), message.size(), pSignature.get(), &len));
        EXPECT_EQ(len, validator.key_size());
    }
}

TEST(nonevalidator_test, signed_fails) {
    std::string message = "Hello World!";
    uint8_t signature[] = "not good!";
    size_t len = strlen((char *) signature);
    NoneValidator validator;

    EXPECT_EQ(false, validator.VerifySignature((uint8_t *) message.c_str(), message.size(), signature, len));
}


TEST(nonevalidator_test, unsigned_succeeds) {
    std::string message = "Hello World!";
    const uint8_t signature[] = "";
    size_t len = 0;
    NoneValidator validator;
    EXPECT_EQ(true, validator.VerifySignature((uint8_t *) message.c_str(), message.size(), signature, len));
}

TEST(nonevalidator_test, signing_clears_len) {
    std::string message = "Hello World!";
    uint8_t signature[] = "not good!";
    size_t len = strlen((char *) signature);
    NoneValidator validator;

    EXPECT_EQ(true, validator.Sign((uint8_t *) message.c_str(), message.size(), signature, &len));
    EXPECT_EQ(0, len);
}
