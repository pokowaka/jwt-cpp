#include "./constants.h"
#include "jwt/allocators.h"
#include "jwt/claimvalidator.h"
#include "jwt/listclaimvalidator.h"
#include "jwt/timevalidator.h"
#include "gtest/gtest.h"
#include <string>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif
#include <jwt/json.hpp>

using json = nlohmann::json;

// Test for the various validators.
TEST(clock, clock_test) {
  UtcClock clk;
  uint64_t now = clk.Now();
#ifdef _WIN32
  Sleep(1000);
#else
  sleep(1);
#endif
  uint64_t later = clk.Now();
  EXPECT_LT(now, later);
}

TEST(iat_test, before) {
  json json = {{"iat", 9}};
  IatValidator iat(0, &fakeClock);
  EXPECT_TRUE(iat.IsValid(json));
}

TEST(iat_test, negative) {
  json json = {{"iat", -9}};
  IatValidator iat(0, &fakeClock);
  ASSERT_THROW(iat.IsValid(json), InvalidClaimError);
}

TEST(iat_test, wrong_type) {
  json json = {{"iat", "foo"}};
  IatValidator iat(0, &fakeClock);
  ASSERT_THROW(iat.IsValid(json), InvalidClaimError);
}

TEST(iat_test, missing) {
  json json = {{"foo", 12}};
  IatValidator iat(0, &fakeClock);
  ASSERT_THROW(iat.IsValid(json), InvalidClaimError);
}

TEST(iat_test, after) {
  json json = {{"iat", 12}};
  IatValidator iat(0, &fakeClock);
  ASSERT_THROW(iat.IsValid(json), InvalidClaimError);
}

TEST(iat_test, before_leeway) {
  json json = {{"iat", 9}};
  IatValidator iat(3, &fakeClock);
  EXPECT_TRUE(iat.IsValid(json));
}

TEST(nbf_test, before) {
  json json = {{"nbf", 9}};
  NbfValidator nbf(0, &fakeClock);
  EXPECT_TRUE(nbf.IsValid(json));
}
TEST(nbf_test, wrong_type) {
  json json = {{"nbf", "foo"}};
  NbfValidator iat(0, &fakeClock);
  ASSERT_THROW(iat.IsValid(json), InvalidClaimError);
}

TEST(nbf_test, missing) {
  json json = {{"foo", 12}};
  NbfValidator nbf(0, &fakeClock);
  ASSERT_THROW(nbf.IsValid(json), InvalidClaimError);
}

TEST(nbf_test, after) {
  json json = {{"nbf", 12}};
  NbfValidator nbf(0, &fakeClock);
  ASSERT_THROW(nbf.IsValid(json), InvalidClaimError);
}

TEST(nbf_test, before_leeway) {
  json json = {{"nbf", 9}};
  NbfValidator nbf(3, &fakeClock);
  EXPECT_TRUE(nbf.IsValid(json));
}

TEST(exp_test, expired) {
  json json = {{"exp", 9}};
  ExpValidator exp(0, &fakeClock);
  ASSERT_THROW(exp.IsValid(json), InvalidClaimError);
}

TEST(exp_test, wrong_type) {
  json json = {{"exp", "foo"}};
  ExpValidator exp(0, &fakeClock);
  ASSERT_THROW(exp.IsValid(json), InvalidClaimError);
}

TEST(exp_test, missing) {
  json json = {{"foo", 12}};
  ExpValidator exp(0, &fakeClock);
  ASSERT_THROW(exp.IsValid(json), InvalidClaimError);
}

TEST(exp_test, not_expired) {
  json json = {{"exp", 12}};
  ExpValidator exp(0, &fakeClock);
  EXPECT_TRUE(exp.IsValid(json));
}

TEST(exp_test, not_expired_leeway) {
  json json = {{"exp", 9}};
  ExpValidator exp(3, &fakeClock);
  EXPECT_TRUE(exp.IsValid(json));
}

std::vector<std::string> accepted = {"foo", "bar"};

TEST(iss_test, missing) {
  json json = {{"foo", "bar"}};
  IssValidator iss(accepted);
  ASSERT_THROW(iss.IsValid(json), InvalidClaimError);
}

TEST(iss_test, wrong_type) {
  json json = {{"iss", 5}};
  IssValidator iss(accepted);
  ASSERT_THROW(iss.IsValid(json), InvalidClaimError);
}

TEST(iss_test, wrong_subject) {
  json json = {{"iss", "baz"}};
  IssValidator iss(accepted);
  ASSERT_THROW(iss.IsValid(json), InvalidClaimError);
}

TEST(iss_test, right_subject) {
  json json = {{"iss", "foo"}};
  IssValidator iss(accepted);
  EXPECT_TRUE(iss.IsValid(json));
}

TEST(sub_test, missing) {
  json json = {{"foo", "bar"}};
  SubValidator sub(accepted);
  ASSERT_THROW(sub.IsValid(json), InvalidClaimError);
}

TEST(sub_test, wrong_type) {
  json json = {{"sub", 5}};
  SubValidator sub(accepted);
  ASSERT_THROW(sub.IsValid(json), InvalidClaimError);
}

TEST(sub_test, wrong_subject) {
  json json = {{"sub", "baz"}};
  SubValidator sub(accepted);
  ASSERT_THROW(sub.IsValid(json), InvalidClaimError);
}

TEST(sub_test, right_subject) {
  json json = {{"sub", "foo"}};
  SubValidator sub(accepted);
  EXPECT_TRUE(sub.IsValid(json));
}

TEST(aud_test, missing) {
  json json = {{"foo", "bar"}};
  AudValidator aud(accepted);
  ASSERT_THROW(aud.IsValid(json), InvalidClaimError);
}

TEST(aud_test, wrong_type) {
  json json = {{"aud", 5}};
  AudValidator aud(accepted);
  ASSERT_THROW(aud.IsValid(json), InvalidClaimError);
}

TEST(aud_test, wrong_subject) {
  json json = json::parse("[\"aud\", \"baz\"]");
  AudValidator aud(accepted);
  ASSERT_THROW(aud.IsValid(json), InvalidClaimError);
}

TEST(aud_test, wrong_subject_from_list) {
  json json = {{"aud", {"baz", "gnu", "cpp"}}};
  AudValidator aud(accepted);
  ASSERT_THROW(aud.IsValid(json), InvalidClaimError);
}

TEST(aud_test, right_subject) {
  json json = {{"aud", "foo"}};
  AudValidator aud(accepted);
  EXPECT_TRUE(aud.IsValid(json));
}

TEST(aud_test, right_subject_from_list) {
  json json = {{"aud", {"bar", "baz", "foo"}}};
  AudValidator aud(accepted);
  EXPECT_TRUE(aud.IsValid(json));
}

TEST(any_test, has_sub) {
  json json = {{"sub", "foo"}};
  AudValidator aud(accepted);
  SubValidator sub(accepted);

  std::vector<ClaimValidator *> claims = {&aud, &sub};
  AnyClaimValidator any(claims);

  EXPECT_TRUE(any.IsValid(json));
}

TEST(any_test, no_aud_no_sub) {
  json json = {{"exp", 9}};
  AudValidator aud(accepted);
  SubValidator sub(accepted);

  std::vector<ClaimValidator *> claims = {&aud, &sub};
  AnyClaimValidator any(claims);

  ASSERT_THROW(any.IsValid(json), InvalidClaimError);
}

TEST(all_test, has_sub_no_aud) {
  json json = {{"sub", "foo"}};
  AudValidator aud(accepted);
  SubValidator sub(accepted);

  std::vector<ClaimValidator *> claims = {&aud, &sub};
  AllClaimValidator all(claims);

  ASSERT_THROW(all.IsValid(json), InvalidClaimError);
}

TEST(all_test, no_aud) {
  json json = {{"sub", "foo"}};
  AudValidator aud(accepted);
  SubValidator sub(accepted);

  std::vector<ClaimValidator *> claims = {&aud, &sub};
  AllClaimValidator all(claims);

  ASSERT_THROW(all.IsValid(json), InvalidClaimError);
}

TEST(all_test, aud_and_sub) {
  json json = {{"sub", "foo"}, {"aud", "bar"}};
  AudValidator aud(accepted);
  SubValidator sub(accepted);

  std::vector<ClaimValidator *> claims = {&aud, &sub};
  AllClaimValidator all(claims);

  EXPECT_TRUE(all.IsValid(json));
}

TEST(option_test, optional_value_missing) {
  json json = {{"aud", "foo"}};
  IssValidator iss(accepted);
  OptionalClaimValidator option(&iss);
  EXPECT_TRUE(option.IsValid(json));
}
