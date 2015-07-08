#include "token/claimset.h"
#include "gtest/gtest.h"
#include <memory>

FakeClock fakeClock(10);

TEST(claimset_test,  no_exp) {
    ClaimSet fakeTimeSet(&fakeClock);

    // No exp set
    EXPECT_EQ(true, fakeTimeSet.Valid());
}

TEST(claimset_test, past_exp) {
    ClaimSet fakeTimeSet(&fakeClock);
    // Past exp
    fakeTimeSet.Add("exp", 11);
    EXPECT_EQ(false, fakeTimeSet.Valid());
}

TEST(claimset_test, before_exp) {
    ClaimSet fakeTimeSet(&fakeClock);
    // Before exp
    fakeTimeSet.Add("exp", 9);
    EXPECT_EQ(true, fakeTimeSet.Valid());
}


TEST(claimset_test, no_iat) {
    ClaimSet fakeTimeSet(&fakeClock);

    // No iat set
    EXPECT_EQ(true, fakeTimeSet.Valid());
}

TEST(claimset_test, past_iat) {
    ClaimSet fakeTimeSet(&fakeClock);
    // Past iat
    fakeTimeSet.Add("iat", 11);
    EXPECT_EQ(true, fakeTimeSet.Valid());
}

TEST(claimset_test, before_iat) {
    ClaimSet fakeTimeSet(&fakeClock);
    // Before iat
    fakeTimeSet.Add("iat", 9);
    EXPECT_EQ(false, fakeTimeSet.Valid());
}

TEST(claimset_test, no_nbf) {
    ClaimSet fakeTimeSet(&fakeClock);

    // No nbf set
    EXPECT_EQ(true, fakeTimeSet.Valid());
}

TEST(claimset_test, past_nbf) {
    ClaimSet fakeTimeSet(&fakeClock);
    // Past nbf
    fakeTimeSet.Add("nbf", 11);
    EXPECT_EQ(false, fakeTimeSet.Valid());
}

TEST(claimset_test, before_nbf) {
    ClaimSet fakeTimeSet(&fakeClock);
    // Before nbf
    fakeTimeSet.Add("nbf", 9);
    EXPECT_EQ(true, fakeTimeSet.Valid());
}


TEST(claimset_test, not_json) {
    std::unique_ptr<ClaimSet> set(ClaimSet::parseJson("fdsfsjljlsf"));
    EXPECT_EQ(nullptr, set.get());
}

TEST(claimset_test, iat_not_a_number) {
    std::unique_ptr<ClaimSet> set(ClaimSet::parseJson("{ \"iat\" : \"foo\" }"));
    EXPECT_EQ(nullptr, set.get());
}

TEST(claimset_test, exp_not_a_number) {
    std::unique_ptr<ClaimSet> set(ClaimSet::parseJson("{ \"exp\" : \"foo\" }"));
    EXPECT_EQ(nullptr, set.get());
}

TEST(claimset_test, nbf_not_a_number) {
    std::unique_ptr<ClaimSet> set(ClaimSet::parseJson("{ \"nbf\" : \"foo\" }"));
    EXPECT_EQ(nullptr, set.get());
}

TEST(claimset_test, take_last) {
    std::unique_ptr<ClaimSet> set(ClaimSet::parseJson("{ \"iss\" : \"first\", \"iss\" : \"last\" }"));
    EXPECT_EQ(nullptr, set.get());
}

TEST(claimset_test, spec_sample) {
    std::unique_ptr<ClaimSet> set(ClaimSet::parseJson(" {\"iss\":\"joe\", \"exp\":1300819380, \"http://example.com/is_root\":true}"));
    EXPECT_NE(nullptr, set.get());
    EXPECT_STREQ("joe", set->Get("iss").c_str());
    EXPECT_STREQ("1300819380", set->Get("exp").c_str());
    EXPECT_STREQ("true", set->Get("http://example.com/is_root").c_str());
}
TEST(claimset_test, jwt_header) {
    std::unique_ptr<ClaimSet> set(ClaimSet::parseJson("{\"alg\":\"HS256\",\"typ\":\"JWT\"}"));
    EXPECT_NE(nullptr, set.get());
    EXPECT_STREQ("HS256", set->Get("alg").c_str());
    EXPECT_STREQ("JWT", set->Get("typ").c_str());
}
