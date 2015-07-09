#include "gtest/gtest.h"
#include <string>
#include "validators/timevalidator.h"
#include "validators/listclaimvalidator.h"

// Test for the various validators.

FakeClock fakeClock(11);

TEST(iat_test, before) {
  auto json = json_pack("{si}", "iat", 9);
  IatValidator iat(0, &fakeClock);
  EXPECT_EQ(true, iat.IsValid(json));
  json_decref(json);
}

TEST(iat_test, wrong_type) {
  auto json = json_pack("{si}", "iat", "foo");
  IatValidator iat(0, &fakeClock);
  EXPECT_EQ(false, iat.IsValid(json));
  json_decref(json);
}

TEST(iat_test, missing) {
  auto json = json_pack("{si}", "foo", 12);
  IatValidator iat(0, &fakeClock);
  EXPECT_EQ(false, iat.IsValid(json));
  json_decref(json);
}

TEST(iat_test, after) {
  auto json = json_pack("{si}", "iat", 12);
  IatValidator iat(0, &fakeClock);
  EXPECT_EQ(false, iat.IsValid(json));
  json_decref(json);
}

TEST(iat_test, before_leeway) {
  auto json = json_pack("{si}", "iat", 9);
  IatValidator iat(3, &fakeClock);
  EXPECT_EQ(true, iat.IsValid(json));
  json_decref(json);
}


TEST(nbf_test, before) {
  auto json = json_pack("{si}", "nbf", 9);
  NbfValidator nbf(0, &fakeClock);
  EXPECT_EQ(true, nbf.IsValid(json));
  json_decref(json);
}

TEST(nbf_test, wrong_type) {
  auto json = json_pack("{ss}", "nbf", "foo");
  NbfValidator iat(0, &fakeClock);
  EXPECT_EQ(false, iat.IsValid(json));
  json_decref(json);
}

TEST(nbf_test, missing) {
  auto json = json_pack("{si}", "foo", 12);
  NbfValidator nbf(0, &fakeClock);
  EXPECT_EQ(false, nbf.IsValid(json));
  json_decref(json);
}

TEST(nbf_test, after) {
  auto json = json_pack("{si}", "nbf", 12);
  NbfValidator nbf(0, &fakeClock);
  EXPECT_EQ(false, nbf.IsValid(json));
  json_decref(json);
}

TEST(nbf_test, before_leeway) {
  auto json = json_pack("{si}", "nbf", 9);
  NbfValidator nbf(3, &fakeClock);
  EXPECT_EQ(true, nbf.IsValid(json));
  json_decref(json);
}

TEST(exp_test, expired) {
  auto json = json_pack("{si}", "exp", 9);
  ExpValidator exp(0, &fakeClock);
  EXPECT_EQ(false, exp.IsValid(json));
  json_decref(json);
}

TEST(exp_test, wrong_type) {
  auto json = json_pack("{ss}", "exp", "foo");
  ExpValidator exp(0, &fakeClock);
  EXPECT_EQ(false, exp.IsValid(json));
  json_decref(json);
}

TEST(exp_test, missing) {
  auto json = json_pack("{si}", "foo", 12);
  ExpValidator exp(0, &fakeClock);
  EXPECT_EQ(false, exp.IsValid(json));
  json_decref(json);
}

TEST(exp_test, not_expired) {
  auto json = json_pack("{si}", "exp", 12);
  ExpValidator exp(0, &fakeClock);
  EXPECT_EQ(true, exp.IsValid(json));
  json_decref(json);
}

TEST(exp_test, not_expired_leeway) {
  auto json = json_pack("{si}", "exp", 9);
  ExpValidator exp(3, &fakeClock);
  EXPECT_EQ(true, exp.IsValid(json));
  json_decref(json);
}

const char* const accepted[] = { "foo", "bar" };

TEST(iss_test, missing) {
  auto json = json_pack("{ss}", "foo", "bar");
  IssValidator iss(accepted, 2);
  EXPECT_EQ(false, iss.IsValid(json));
  json_decref(json);
}

TEST(iss_test, wrong_type) {
  auto json = json_pack("{si}", "iss", 5);
  IssValidator iss(accepted, 2);
  EXPECT_EQ(false, iss.IsValid(json));
  json_decref(json);
}

TEST(iss_test, wrong_subject) {
  auto json = json_pack("{ss}", "iss", "baz");
  IssValidator iss(accepted, 2);
  EXPECT_EQ(false, iss.IsValid(json));
  json_decref(json);
}

TEST(iss_test, right_subject) {
  auto json = json_pack("{ss}", "iss", "foo");
  IssValidator iss(accepted, 2);
  EXPECT_EQ(true, iss.IsValid(json));
  json_decref(json);
}

TEST(sub_test, missing) {
  auto json = json_pack("{ss}", "foo", "bar");
  SubValidator sub(accepted, 2);
  EXPECT_EQ(false, sub.IsValid(json));
  json_decref(json);
}

TEST(sub_test, wrong_type) {
  auto json = json_pack("{si}", "sub", 5);
  SubValidator sub(accepted, 2);
  EXPECT_EQ(false, sub.IsValid(json));
  json_decref(json);
}

TEST(sub_test, wrong_subject) {
  auto json = json_pack("{ss}", "sub", "baz");
  SubValidator sub(accepted, 2);
  EXPECT_EQ(false, sub.IsValid(json));
  json_decref(json);
}

TEST(sub_test, right_subject) {
  auto json = json_pack("{ss}", "sub", "foo");
  SubValidator sub(accepted, 2);
  EXPECT_EQ(true, sub.IsValid(json));
  json_decref(json);
}

TEST(aud_test, missing) {
  auto json = json_pack("{ss}", "foo", "bar");
  AudValidator aud(accepted, 2);
  EXPECT_EQ(false, aud.IsValid(json));
  json_decref(json);
}

TEST(aud_test, wrong_type) {
  auto json = json_pack("{si}", "aud", 5);
  AudValidator aud(accepted, 2);
  EXPECT_EQ(false, aud.IsValid(json));
  json_decref(json);
}

TEST(aud_test, wrong_subject) {
  auto json = json_pack("{ss}", "aud", "baz");
  AudValidator aud(accepted, 2);
  EXPECT_EQ(false, aud.IsValid(json));
  json_decref(json);
}

TEST(aud_test, right_subject) {
  auto json = json_pack("{ss}", "aud", "foo");
  AudValidator aud(accepted, 2);
  EXPECT_EQ(true, aud.IsValid(json));
  json_decref(json);
}

TEST(any_test, has_sub) {
  auto json = json_pack("{ss}", "sub", "foo");
  AudValidator aud(accepted, 2);
  SubValidator sub(accepted, 2);

  ClaimValidator* claims[] = { &aud, &sub };
  AnyClaimValidator any(claims, 2);

  EXPECT_EQ(true, any.IsValid(json));
  json_decref(json);
}

TEST(any_test, no_aud_no_sub) {
  auto json = json_pack("{si}", "exp", 9);
  AudValidator aud(accepted, 2);
  SubValidator sub(accepted, 2);

  ClaimValidator* claims[] = { &aud, &sub };
  AnyClaimValidator any(claims, 2);

  EXPECT_EQ(false, any.IsValid(json));
  json_decref(json);
}

TEST(all_test, no_aud) {
  auto json = json_pack("{ss}", "sub", "foo");
  AudValidator aud(accepted, 2);
  SubValidator sub(accepted, 2);

  ClaimValidator* claims[] = { &aud, &sub };
  AllClaimValidator all(claims, 2);

  EXPECT_EQ(false, all.IsValid(json));
  json_decref(json);
}

TEST(all_test, aud_and_sub) {
  auto json = json_pack("{ss, ss}", "sub", "foo", "aud", "bar");
  AudValidator aud(accepted, 2);
  SubValidator sub(accepted, 2);

  ClaimValidator* claims[] = { &aud, &sub };
  AllClaimValidator all(claims, 2);

  EXPECT_EQ(true, all.IsValid(json));
  json_decref(json);
}


