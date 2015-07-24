#include <string>
#include "gtest/gtest.h"
#include "./constants.h"
#include "jwt/allocators.h"
#include "jwt/claimvalidator.h"
#include "jwt/listclaimvalidator.h"
#include "jwt/timevalidator.h"

// Test for the various validators.

TEST(iat_test, before) {
  json_ptr json(json_pack("{si}", "iat", 9));
  IatValidator iat(0, &fakeClock);
  EXPECT_TRUE(iat.IsValid(json.get()));
}

TEST(iat_test, wrong_type) {
  json_ptr json(json_pack("{si}", "iat", "foo"));
  IatValidator iat(0, &fakeClock);
  ASSERT_THROW(iat.IsValid(json.get()), InvalidClaimError);
}

TEST(iat_test, missing) {
  json_ptr json(json_pack("{si}", "foo", 12));
  IatValidator iat(0, &fakeClock);
  ASSERT_THROW(iat.IsValid(json.get()), InvalidClaimError);
}

TEST(iat_test, after) {
  json_ptr json(json_pack("{si}", "iat", 12));
  IatValidator iat(0, &fakeClock);
  ASSERT_THROW(iat.IsValid(json.get()), InvalidClaimError);
}

TEST(iat_test, before_leeway) {
  json_ptr json(json_pack("{si}", "iat", 9));
  IatValidator iat(3, &fakeClock);
  EXPECT_TRUE(iat.IsValid(json.get()));
}


TEST(nbf_test, before) {
  json_ptr json(json_pack("{si}", "nbf", 9));
  NbfValidator nbf(0, &fakeClock);
  EXPECT_TRUE(nbf.IsValid(json.get()));
}

TEST(nbf_test, wrong_type) {
  json_ptr json(json_pack("{ss}", "nbf", "foo"));
  NbfValidator iat(0, &fakeClock);
  ASSERT_THROW(iat.IsValid(json.get()), InvalidClaimError);
}

TEST(nbf_test, missing) {
  json_ptr json(json_pack("{si}", "foo", 12));
  NbfValidator nbf(0, &fakeClock);
  ASSERT_THROW(nbf.IsValid(json.get()), InvalidClaimError);
}

TEST(nbf_test, after) {
  json_ptr json(json_pack("{si}", "nbf", 12));
  NbfValidator nbf(0, &fakeClock);
  ASSERT_THROW(nbf.IsValid(json.get()), InvalidClaimError);
}

TEST(nbf_test, before_leeway) {
  json_ptr json(json_pack("{si}", "nbf", 9));
  NbfValidator nbf(3, &fakeClock);
  EXPECT_TRUE(nbf.IsValid(json.get()));
}

TEST(exp_test, expired) {
  json_ptr json(json_pack("{si}", "exp", 9));
  ExpValidator exp(0, &fakeClock);
  ASSERT_THROW(exp.IsValid(json.get()), InvalidClaimError);
}

TEST(exp_test, wrong_type) {
  json_ptr json(json_pack("{ss}", "exp", "foo"));
  ExpValidator exp(0, &fakeClock);
  ASSERT_THROW(exp.IsValid(json.get()), InvalidClaimError);
}

TEST(exp_test, missing) {
  json_ptr json(json_pack("{si}", "foo", 12));
  ExpValidator exp(0, &fakeClock);
  ASSERT_THROW(exp.IsValid(json.get()), InvalidClaimError);
}

TEST(exp_test, not_expired) {
  json_ptr json(json_pack("{si}", "exp", 12));
  ExpValidator exp(0, &fakeClock);
  EXPECT_TRUE(exp.IsValid(json.get()));
}

TEST(exp_test, not_expired_leeway) {
  json_ptr json(json_pack("{si}", "exp", 9));
  ExpValidator exp(3, &fakeClock);
  EXPECT_TRUE(exp.IsValid(json.get()));
}

const char *const accepted[] = {"foo", "bar"};

TEST(iss_test, missing) {
  json_ptr json(json_pack("{ss}", "foo", "bar"));
  IssValidator iss(accepted, 2);
  ASSERT_THROW(iss.IsValid(json.get()), InvalidClaimError);
}

TEST(iss_test, wrong_type) {
  json_ptr json(json_pack("{si}", "iss", 5));
  IssValidator iss(accepted, 2);
  ASSERT_THROW(iss.IsValid(json.get()), InvalidClaimError);
}

TEST(iss_test, wrong_subject) {
  json_ptr json(json_pack("{ss}", "iss", "baz"));
  IssValidator iss(accepted, 2);
  ASSERT_THROW(iss.IsValid(json.get()), InvalidClaimError);
}

TEST(iss_test, right_subject) {
  json_ptr json(json_pack("{ss}", "iss", "foo"));
  IssValidator iss(accepted, 2);
  EXPECT_TRUE(iss.IsValid(json.get()));
}

TEST(sub_test, missing) {
  json_ptr json(json_pack("{ss}", "foo", "bar"));
  SubValidator sub(accepted, 2);
  ASSERT_THROW(sub.IsValid(json.get()), InvalidClaimError);
}

TEST(sub_test, wrong_type) {
  json_ptr json(json_pack("{si}", "sub", 5));
  SubValidator sub(accepted, 2);
  ASSERT_THROW(sub.IsValid(json.get()), InvalidClaimError);
}

TEST(sub_test, wrong_subject) {
  json_ptr json(json_pack("{ss}", "sub", "baz"));
  SubValidator sub(accepted, 2);
  ASSERT_THROW(sub.IsValid(json.get()), InvalidClaimError);
}

TEST(sub_test, right_subject) {
  json_ptr json(json_pack("{ss}", "sub", "foo"));
  SubValidator sub(accepted, 2);
  EXPECT_TRUE(sub.IsValid(json.get()));
}

TEST(aud_test, missing) {
  json_ptr json(json_pack("{ss}", "foo", "bar"));
  AudValidator aud(accepted, 2);
  ASSERT_THROW(aud.IsValid(json.get()), InvalidClaimError);
}

TEST(aud_test, wrong_type) {
  json_ptr json(json_pack("{si}", "aud", 5));
  AudValidator aud(accepted, 2);
  ASSERT_THROW(aud.IsValid(json.get()), InvalidClaimError);
}

TEST(aud_test, wrong_subject) {
  json_ptr json(json_pack("{ss}", "aud", "baz"));
  AudValidator aud(accepted, 2);
  ASSERT_THROW(aud.IsValid(json.get()), InvalidClaimError);
}

TEST(aud_test, wrong_subject_from_list) {
  json_ptr json(json_pack("{s[sss]}", "aud", "baz", "gnu", "cpp"));
  AudValidator aud(accepted, 2);
  ASSERT_THROW(aud.IsValid(json.get()), InvalidClaimError);
}

TEST(aud_test, right_subject) {
  json_ptr json(json_pack("{ss}", "aud", "foo"));
  AudValidator aud(accepted, 2);
  EXPECT_TRUE(aud.IsValid(json.get()));
}

TEST(aud_test, right_subject_from_list) {
  json_ptr json(json_pack("{s[sss]}", "aud", "bar", "baz", "foo"));
  AudValidator aud(accepted, 2);
  EXPECT_TRUE(aud.IsValid(json.get()));
}

TEST(any_test, has_sub) {
  json_ptr json(json_pack("{ss}", "sub", "foo"));
  AudValidator aud(accepted, 2);
  SubValidator sub(accepted, 2);

  ClaimValidator *claims[] = {&aud, &sub};
  AnyClaimValidator any(claims, 2);

  EXPECT_TRUE(any.IsValid(json.get()));
}

TEST(any_test, no_aud_no_sub) {
  json_ptr json(json_pack("{si}", "exp", 9));
  AudValidator aud(accepted, 2);
  SubValidator sub(accepted, 2);

  ClaimValidator *claims[] = {&aud, &sub};
  AnyClaimValidator any(claims, 2);

  ASSERT_THROW(any.IsValid(json.get()), InvalidClaimError);
}

TEST(all_test, no_aud) {
  json_ptr json(json_pack("{ss}", "sub", "foo"));
  AudValidator aud(accepted, 2);
  SubValidator sub(accepted, 2);

  ClaimValidator *claims[] = {&aud, &sub};
  AllClaimValidator all(claims, 2);

  ASSERT_THROW(all.IsValid(json.get()), InvalidClaimError);
}

TEST(all_test, aud_and_sub) {
  json_ptr json(json_pack("{ss, ss}", "sub", "foo", "aud", "bar"));
  AudValidator aud(accepted, 2);
  SubValidator sub(accepted, 2);

  ClaimValidator *claims[] = {&aud, &sub};
  AllClaimValidator all(claims, 2);

  EXPECT_TRUE(all.IsValid(json.get()));
}

TEST(option_test, optional_value_missing) {
  json_ptr json(json_pack("{ss}", "aud", "foo"));
  IssValidator iss(accepted, 2);
  OptionalClaimValidator option(&iss);
  EXPECT_TRUE(option.IsValid(json.get()));
}
