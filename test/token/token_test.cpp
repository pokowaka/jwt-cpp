#include <validators/claims/listclaimvalidator.h>
#include "gtest/gtest.h"
#include "token/token.h"
#include "token/keymastertoken.h"
#include "validators/hmacvalidator.h"
#include "util/allocators.h"
#include <jansson.h>
#include <validators/rsavalidator.h>
#include "token/jwsverifier.h"

#define MANY_TIMES_TOKEN 500

TEST(token_test, missing_payload) {
    std::string tokenstr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkJBUiJ9";
    std::unique_ptr<Token> token(Token::Parse(tokenstr.c_str(), tokenstr.size()));

    EXPECT_EQ(nullptr, token);
}


TEST(token_test, missing_signature) {
    std::string tokenstr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9";
    std::unique_ptr<Token> token(Token::Parse(tokenstr.c_str(), tokenstr.size()));

    EXPECT_EQ(nullptr, token);
}

TEST(token_test, valid) {
    std::string tokenstr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
    std::unique_ptr<Token> token(Token::Parse(tokenstr.c_str(), tokenstr.size()));
    ASSERT_NE(nullptr, token);

    const json_t *header = token->header_claims();
    EXPECT_EQ(false, token->IsEncrypted());
    EXPECT_STREQ("JWT", json_string_value(json_object_get(header, "typ")));
}

TEST(token_test, encoded) {
  HS256Validator validator("secret");
  JwsVerifier verifier(&validator);
  unique_json_ptr json(json_pack("{ss, ss, sb}", "sub", "1234567890", "name", "John Doe", "admin", true));
  str_ptr str_token(Token::Encode(json.get(), &validator));


  // We should have a token
  ASSERT_NE(nullptr, str_token.get());

  // That we can actually parse verify
  std::unique_ptr<Token> token(Token::Parse(str_token.get(), strlen(str_token.get())));
  EXPECT_EQ(true, token->VerifySignature(&verifier));
}

TEST(token_test, signed) {
    std::string tokenstr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
    std::unique_ptr<Token> token(Token::Parse(tokenstr.c_str(), tokenstr.size()));
    HS256Validator validator("secret");
    JwsVerifier verifier(&validator);

    const char* const accepted[] = { "1234567890", "bar" };
    SubValidator sub(accepted, 2);

    EXPECT_EQ(true, token->VerifySignature(&verifier));
    EXPECT_EQ(true, token->VerifyClaims(&sub));
}

TEST(token_test, parse_and_validate) {
    HS256Validator validator("secret");
    JwsVerifier verifier(&validator);

    const char* const accepted[] = { "1234567890", "bar" };
    SubValidator sub(accepted, 2);

    std::string tokenstr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
    std::unique_ptr<Token> token(Token::Parse(tokenstr.c_str(), tokenstr.size(), &verifier, &sub));

    EXPECT_TRUE(token.get() != NULL);
}

TEST(token_test, parse_and_validate_bad_signature) {
    HS512Validator validator("not_your_secret");
    JwsVerifier verifier(&validator);

    const char* const accepted[] = { "1234567890", "bar" };
    SubValidator sub(accepted, 2);

    std::string tokenstr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
    std::unique_ptr<Token> token(Token::Parse(tokenstr.c_str(), tokenstr.size(), &verifier, &sub));

    EXPECT_TRUE(token.get() == NULL);
}

TEST(token_test, parse_and_validate_bad_claims) {
    HS256Validator validator("secret");
    JwsVerifier verifier(&validator);

    const char* const accepted[] = { "foo", "bar" };
    SubValidator sub(accepted, 2);

    std::string tokenstr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
    std::unique_ptr<Token> token(Token::Parse(tokenstr.c_str(), tokenstr.size(), &verifier, &sub));

    EXPECT_TRUE(token.get() == NULL);
}

TEST(token_test, payload_deserialize) {
    std::string tokenstr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
    std::unique_ptr<Token> token(Token::Parse(tokenstr.c_str(), tokenstr.size()));
    HS256Validator validator("secret");
    JwsVerifier verifier(&validator);


    json_t *payload = token->payload_claims();
    EXPECT_STREQ("1234567890", json_string_value(json_object_get(payload, "sub")));
    EXPECT_EQ(true, json_boolean_value(json_object_get(payload, "admin")));
    EXPECT_STREQ("John Doe", json_string_value(json_object_get(payload, "name")));
}


TEST(token_test, perf_signed) {
    // std::string tokenstr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
    std::string tokenstr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.ueNf9M7B1LolUMR-9Rgnk-bPyzSbMeSW2fWI598ruCELjES2lEadXw38kCiZ1RGP7LS5pf272IrFMi3aYxaFBw";
    //HS256Validator validator("secret");
    HS512Validator validator("secret");
    JwsVerifier verifier(&validator);

    for (int i = 0; i < MANY_TIMES_TOKEN; i++) {
        std::unique_ptr<Token> token(Token::Parse(tokenstr.c_str(), tokenstr.size()));
        EXPECT_EQ(true, token->VerifySignature(&verifier));
        EXPECT_NE(nullptr, token->payload_claims());
    }
}

TEST(token_test, keymaster_perf) {
  std::string keymaster_token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDIiwiaXYiOiJLOWxpL2Y3WTB0Mng2UE5RZXltM0JnPT1cbiIsImtpZCI6Mn0.enVvDwF02krF-Bhbd4xnaMtsd0-nqnCoj_NSXA1x5xndJ0bqaxQGtgMEcgTbyAXBwCTEAe8krpj_Uga781jPCe_XJCZqgU6bciRqtaqUrmJeBIVaiGnLym23ihK_uBN7U74F27IdiL2ZVW3XLJfW9-HONjuiFhKdavejStUzCbUoAaVe_qvGxV8I2U2NBBBgwjgp4FoxQsIMUOaWyJ17Y8N8CPKsVRTGgF51q7SAJ6IZJyfTylXL6wQFb20OTsKwikpdkNj04KSFHF0FpAHtZIHj4rCcv8Ah6F02g4yYeSirJASHxEpxKtGpSU3DRour3zIjLFgoJLNb3Y1WGcE5bWYLv7ozMm9Zp-auwL4hi0rQ8qVb6qisjYzkh-bafApdkJrZ6rUxDJNQ_9DLE_xhwzti6Tng0jncVSopPifCL0JHU8n9R_1tD0QWposztlZl4WK5iBuIQDgaeCi4EQUm3K8xrHDqy9rGRJiU_QcGUHpzHVUNx78mhe7_ieba2Jn6RdpwcNALO1KJl130Hbn6OIvHc0pnEVCPSuN494RDnacx4p2HRySsvX_O2edh2bJ2Jg4SKR2EZwuNMUdehRlk_SPTCC1k9XRM2_VrtCKroJdM5uM4Tu7zk0COkvkBLO2pIQXuCBkrPxS2nKMiVjv2ALH3VKLD9GK_ZzeQmcdPNgY.Mf_CuMrN9E_fzWmGsHxLh3jmYeIgJt2Cv0N3ys_s-8OtCGdnlZbNoHIP0joztbRD_BkBqftM3SIl3I8WW-BOtBUNfFJWpZL8AbWj5UNU7gxqoXzO97VhAd90jQ3_1Fex7xA1g4YK9C1HUngQe-i6RVnfLEHCLUvOVNBT-CQqR8Dl201qIUvo6chXPaD1Ai7N-C6L5hMMF_TSovjXUycHjzSxk21HHNcDWx1CZfJ6yr3LSItBSGGlLlvCqWnmIq7fKuwNpjTnwVn1WDfZaF6G3H5ET4_Yo5LZAOqVjwKTGI9o69fKvw9mQ1AxEEoQkkAt2uCTSW-kR4C1vyhBEzv5ajRZIrsPAlwz8UmFpDWXVlHyigBBKtwuA3xZkU9oCO6Qtao-CBFyj-qlIyrTKRmbRxAneH8Y4pRkt3HQ1P92StwfdVvSs3O7DU8crT759fl25TdILAHEn2k_Au3Azczxv95WJWAlFQeuL9cFFuzvp51EdwVdBH5zprg-fmwMm3oBr5803uiGs_QYxVCLFJTPybiw0nGxn5ssbauMGwqkGrXNuMXXE22h_wcZ1YQDWkTWcFSkT_n3Z-z_guzrX9uOXzYDz6l_1bFUh3B6XbLHgr3OCvx9uoC9B8L-W6ooRzZ1qH1EE38-MuJjJ4kgsZhFI2t4Y03fUBvdstthWahgzCxNqRtmCJuyLl1t4p9MK7FAfBQV5ujr0XdN6o_pEBv20VzD_NxtwYZKfxb77hLtyIeXJ7iOMORk6Not1wlOxDWxt8RGOWfQw0yIDBIolONCMtkqYTfWFyhxK_arIdp-1fzO74rKlXRzb5EUb95XYC_5pULsUIPdMAHjh5kgTxOkX3BdZU6G9E8SJhUbeLZUpzPPC6h3ldN3wEm2yb4YRKoFFmeT90jPUX1kAvcpu18OxwTHasNIzE6YcR42SNlSjWTFl91iBgVNJAqMLhRL3dG1-yAOlS3Hzb6NuUJCKiN9hsx0-MJRQUkY9ShEGFBh0TOQwu71W5yERz_OvZ8P3WBCfOSiatl9yFXZh6eJQ2vr1enFrAz3tPW0YNdkQKJaCvUl0kmWH4FvcMCQt1VU1ecrbz4S4Kd3Nzd8kdEbcgXar0pcOx7yxxF1C2OApi7CRSqWDY2Bez3TKaJVFuqJA3NB-NggV3SI6775Dlp_eFSFupcgYWv_aMj0Yuk873VksmG6tcZ1Z7ogGMBb3mIlCqFiRa7ZFaZJEx8783WIc7UxRAHP6GltrKGC8BwnkNyOSuIngt6wizkBAtL9vgPWfcjh5VAXcvtjtcpWO6CIOZBk7ZbUGoGwyIQSmRnpnMNbbgA";
  std::string private_key = "-----BEGIN RSA PRIVATE KEY-----\n"
    "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\n"
    "-----END RSA PRIVATE KEY-----";

  std::string pubkey = "-----BEGIN PUBLIC KEY-----\n"
    "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuVHVSuelwW+xZCvrMg73\n"
    "cms1eAkCd2vz6B+PgLlJ98MGYqwrsaLkJT3RnS4D4lQ/q3U4Z6fT6DLtF+4dltEt\n"
    "pNspcy6arJNYdjjwwirIYoDFzVvLeShnLUJ95X9x9/JapnM7Hne4vEiDrXk/67cW\n"
    "4ETed3Syu9Pc170stoU6GSApIq/vfUPleU+AqDi8USNoLedZNQfzEZUJZj8eLfzb\n"
    "NbgXDXnkHKU38TRv/AWjw5aV4TtF/PlE9eim1Umxmu4e1leR1I27bBlijk37FwEw\n"
    "WqVbr6KAHGbXfL0Y9KY5eddzy7EqTEs5wDhS1MKGx/muge3QA0eKnAkgfU+mLkqv\n"
    "YiTWNOVtTaFy7gmJIK7pNjQZGVqQ0sQD7DGkOs5u3CXE5j4TxmlGg0g2r8i67Xv2\n"
    "7RCeI74vOLVqJHXzXnq/UJQWPIiBvmeUn6EnU/bJhv/2L38KhVk97MzWfAbg7+35\n"
    "oCVgqsWieQAikSZxc1kTOy1eFknmJdzxRb5LH3dFI5YISntzJgg4OyJrzgAqHHYn\n"
    "TpYXBkWkARWXwEHwEIAlHgTurL7dUh4MavVh0pyNidXfr9KPyhfhWQJg4Tle9rq5\n"
    "awQYcgcwYQcxeeN2Hf0qF+PrZDD5hnEvgpfH4r/Xtzm1/bDxj6DFb3is2VqbhgGL\n"
    "zURMHrE6g4CGkyUbActBc88CAwEAAQ==\n"
    "-----END PUBLIC KEY-----";

    Jwe decrypter(private_key.c_str());
    RS512Validator validator(pubkey);
    JwsVerifier verifier(&validator);

    for(int i = 0; i < 50; i++) {
      std::unique_ptr<Token> token(KeymasterToken::decrypt_and_verify(keymaster_token.c_str(), keymaster_token.size(),
            &decrypter, &verifier));
      EXPECT_NE(nullptr, token.get());
    }
}

TEST(token_test, keymaster_token) {
    std::string keymaster_token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDIiwiaXYiOiJLOWxpL2Y3WTB0Mng2UE5RZXltM0JnPT1cbiIsImtpZCI6Mn0.enVvDwF02krF-Bhbd4xnaMtsd0-nqnCoj_NSXA1x5xndJ0bqaxQGtgMEcgTbyAXBwCTEAe8krpj_Uga781jPCe_XJCZqgU6bciRqtaqUrmJeBIVaiGnLym23ihK_uBN7U74F27IdiL2ZVW3XLJfW9-HONjuiFhKdavejStUzCbUoAaVe_qvGxV8I2U2NBBBgwjgp4FoxQsIMUOaWyJ17Y8N8CPKsVRTGgF51q7SAJ6IZJyfTylXL6wQFb20OTsKwikpdkNj04KSFHF0FpAHtZIHj4rCcv8Ah6F02g4yYeSirJASHxEpxKtGpSU3DRour3zIjLFgoJLNb3Y1WGcE5bWYLv7ozMm9Zp-auwL4hi0rQ8qVb6qisjYzkh-bafApdkJrZ6rUxDJNQ_9DLE_xhwzti6Tng0jncVSopPifCL0JHU8n9R_1tD0QWposztlZl4WK5iBuIQDgaeCi4EQUm3K8xrHDqy9rGRJiU_QcGUHpzHVUNx78mhe7_ieba2Jn6RdpwcNALO1KJl130Hbn6OIvHc0pnEVCPSuN494RDnacx4p2HRySsvX_O2edh2bJ2Jg4SKR2EZwuNMUdehRlk_SPTCC1k9XRM2_VrtCKroJdM5uM4Tu7zk0COkvkBLO2pIQXuCBkrPxS2nKMiVjv2ALH3VKLD9GK_ZzeQmcdPNgY.Mf_CuMrN9E_fzWmGsHxLh3jmYeIgJt2Cv0N3ys_s-8OtCGdnlZbNoHIP0joztbRD_BkBqftM3SIl3I8WW-BOtBUNfFJWpZL8AbWj5UNU7gxqoXzO97VhAd90jQ3_1Fex7xA1g4YK9C1HUngQe-i6RVnfLEHCLUvOVNBT-CQqR8Dl201qIUvo6chXPaD1Ai7N-C6L5hMMF_TSovjXUycHjzSxk21HHNcDWx1CZfJ6yr3LSItBSGGlLlvCqWnmIq7fKuwNpjTnwVn1WDfZaF6G3H5ET4_Yo5LZAOqVjwKTGI9o69fKvw9mQ1AxEEoQkkAt2uCTSW-kR4C1vyhBEzv5ajRZIrsPAlwz8UmFpDWXVlHyigBBKtwuA3xZkU9oCO6Qtao-CBFyj-qlIyrTKRmbRxAneH8Y4pRkt3HQ1P92StwfdVvSs3O7DU8crT759fl25TdILAHEn2k_Au3Azczxv95WJWAlFQeuL9cFFuzvp51EdwVdBH5zprg-fmwMm3oBr5803uiGs_QYxVCLFJTPybiw0nGxn5ssbauMGwqkGrXNuMXXE22h_wcZ1YQDWkTWcFSkT_n3Z-z_guzrX9uOXzYDz6l_1bFUh3B6XbLHgr3OCvx9uoC9B8L-W6ooRzZ1qH1EE38-MuJjJ4kgsZhFI2t4Y03fUBvdstthWahgzCxNqRtmCJuyLl1t4p9MK7FAfBQV5ujr0XdN6o_pEBv20VzD_NxtwYZKfxb77hLtyIeXJ7iOMORk6Not1wlOxDWxt8RGOWfQw0yIDBIolONCMtkqYTfWFyhxK_arIdp-1fzO74rKlXRzb5EUb95XYC_5pULsUIPdMAHjh5kgTxOkX3BdZU6G9E8SJhUbeLZUpzPPC6h3ldN3wEm2yb4YRKoFFmeT90jPUX1kAvcpu18OxwTHasNIzE6YcR42SNlSjWTFl91iBgVNJAqMLhRL3dG1-yAOlS3Hzb6NuUJCKiN9hsx0-MJRQUkY9ShEGFBh0TOQwu71W5yERz_OvZ8P3WBCfOSiatl9yFXZh6eJQ2vr1enFrAz3tPW0YNdkQKJaCvUl0kmWH4FvcMCQt1VU1ecrbz4S4Kd3Nzd8kdEbcgXar0pcOx7yxxF1C2OApi7CRSqWDY2Bez3TKaJVFuqJA3NB-NggV3SI6775Dlp_eFSFupcgYWv_aMj0Yuk873VksmG6tcZ1Z7ogGMBb3mIlCqFiRa7ZFaZJEx8783WIc7UxRAHP6GltrKGC8BwnkNyOSuIngt6wizkBAtL9vgPWfcjh5VAXcvtjtcpWO6CIOZBk7ZbUGoGwyIQSmRnpnMNbbgA";

    std::string private_key = "-----BEGIN RSA PRIVATE KEY-----\n"
      "MIIJKQIBAAKCAgEA3LKLvLOvdAY/WsGhUpE5xjeYCRB1LqsbkwyyU6nVvSP85QNK\n"
      "W6RPVY0qy80ZbAYfsYr4BdpTgVrpyc2lXuyFlRa+EBuCwdSnM/8UHzu7UYJwtG2V\n"
      "QZUxTHtT6V70QXLR8lMn7s7bmEsaEnbvp+vamvBS1NhwsgaTKx1vjJAcaMabQzDQ\n"
      "RUI2vuB1JtEry3RlsUGsUwf/HOrI7FqiYda4Hzyck/hkpv3rLzAc3cFU42jnXXK2\n"
      "YQNaz3oS4HvbcL2OOnrDxuYn4FDvMLd1OMJz+ry6sDrq+2LvubW79fr7YLn9Rztk\n"
      "NN0ObGiKYO2pCehawHIhyM41Ucl1DwVf4zfSa6N5GcAy5+HFOiMsi4xZ8C4r6AqR\n"
      "hNQZWqn7gAdw6mfCoguMVFqqcSt+HFtQ2k+D1cJEfNAoFG9lWRrDdhIfpqEfnekY\n"
      "asTMtfH97h+8v2G2iLufF5o7fmvM1e/VYnWucGGnfEOE7tN1xSUH0o2XsADkSecc\n"
      "ZEjEy3pa+iGtzgZZV4qdkDu3fDjg0JpcEeDSKS0kaaNNcmtBlRDOp0iN2t17+wO0\n"
      "mp+cynDMNjfacF8ePBreFdEjM1ftEYNDrww+diLx9pHQYE44YBcg6Tiwk2xooziQ\n"
      "NJRjESqQ4/yWcBc3GU8uSxOiEZ37ml8PPbKVD97ujVqo714aYTf/SNddOE8CAwEA\n"
      "AQKCAgBMmQN62Pp6UHjIrQ+qspDUxRLVgorJScXmQa/a7cUrQkRRz9SM/fgy/y3t\n"
      "UiASqAVz/4GZtm7pJH6j9eYBjiHG3v/UY1f8oivuFggL1xVqctVfKfF1s6xKmTtE\n"
      "chpgZNONQWNItS7uKpK/+duv8mILCIIXMY/bmgCWJD9FD/dsPhJBPb3ra9HIaer/\n"
      "L/X9RUbOQLbokovuo2Zc8hAN2RJKdST7DmkQtGxeElrSdHlb/FrgyiGWhi2MeRf4\n"
      "JcTB2mh0z4sHi3Ynmq+JvwLGUmcijUJWS/ymh24gjHzSIOwCZEsN4AUle9u3sIjm\n"
      "n1XeBHEK/hHPuhIzcrJYJktjd0pmQHQTL6sQGsVQjZFC3Gm8mgJ9B0hO/ec8mXK7\n"
      "iIu46Sm2owgCqW+7mRDXcVhNKCJVSnmZCHIPyFSORp7C8wJfjNCFFNrtYf0tDyce\n"
      "fwcgEpERCtMzTLK2hXvtSXBh2dmDOg1H9olw2KkWAMBbn8QFctUMbgU5f1RIgRoR\n"
      "0pTQCfDDQXgqZuvT77C1ObqEn2/GFf9GNKUa0AqxTM35mtBJB0sK69jTzate+yzM\n"
      "QnzxzEtODwzCC/D0u9hFJE1XatD9gXqDJk0XscohQNY40FRmm7zlVVRUzAmnDSdR\n"
      "uNoqoDlNwIUaRxvtqRpVV9v5O2y8BYBYF3lDteYgluPX/p+bAQKCAQEA77UQW+Yd\n"
      "5cWizysFzlbw1uTViE7XxfdBBVq0keBONbrsPSPDzz5w4mtHJOLpixtf1Ktb9enY\n"
      "Ek3kx7b4lWjfYPz4ae7U4w3l0KIO6SCqRW+qcyVloVapmF8BGcHZNrZPfEdG543A\n"
      "k5AL+nWo1+HKHkjdCgTAua9XKVEGlCQoEjFZo1uEEJ0SbVtvFBQTQn8/f3UGb+3J\n"
      "RoVBqvDTaTRIrbOPYmLpZbj60RmWwl95sr3B5HhrVw+DD6awvASJhXIAtY/HYje+\n"
      "6bPOebKNCE0MYFyp84qzqRjomC3bcSqKOUTQfRCZdbAkthCSVDHLEC+z2tBuEOXm\n"
      "OotlgrNEHzZcjwKCAQEA67K1Xe1OdFFl6PP9Sylo3jtmlY763jVAA5SbKX3GnaQK\n"
      "Y2+uWnWZ28NBl/F65x+U3pjL1XVy7BFeuYAJOnnt0YAm41oXNfgthLDqpX7aUblV\n"
      "UHanr8Kxe9y6Dp+wHgAEZ2g+gAhLdznyOsYQxJfhFMCqCET0swLoj/JC0ueYgdJa\n"
      "NkXO3OcaxQ213M95nFDqMuF4ABUXz0AUvL0YIn8vpR+1rR3sqwJZWl8BsrzM7Uge\n"
      "QePouupUxbs2qBxT3yqLaeq4Nt0xvF/MlC+EhQ5ATFyishsoAKspdo+dYAwJOZVM\n"
      "VY/DQxJxYoy2N+oErrV/03K3olgDLu148HgsCcDIQQKCAQBv6FQO00u57Z6ooSlA\n"
      "v44IhSS7UjOiFGCio0oRoGpi4zVPBddwdXI2AmdgbR8i9lCy9J0mHVnmkb7xDhbX\n"
      "ifJfUTqYGgwBRIe58y6K39keOZeV0iu0OsVKgW/+GmXSCSLqnkwX5jG1slYlQ7Dj\n"
      "uGGn6dRnzPg8uAM1IsKzfn3GoIt8nEj3iJ0FuN4OvaCQNt/qHTQ4JQcGiUezCmNo\n"
      "hiQ4E9Ao2oykFMvjutKLRA+IxtYyV5WlO3SwZd20qVmalzKFkO5AiE30xSDr59O3\n"
      "wGC6zAf7zxE5LIvKH/6GwpltSxcajBlYvDcnWG04KVbn451P1mbMNMhbJKDrd82h\n"
      "1Ls5AoIBAQCWyWqcX4AMjDKdWNKX7jMH0YqsbZ9y3zBH2h916OBS46o9uSoa9xdq\n"
      "b70b/sH48Mxlp+znb88I1Yf7Nr0wquaJW+oFExK8VTyRojlLjR8Qn3fEFVTr7ats\n"
      "KWbiiii62Jn4qckqUaQt72VXUnVRwDSf+S4OQkcl6ttrk7pKgR2hGDjcdcaErlkC\n"
      "7eWGETmk1mMuD+6cZuInlcBuiq7RCvspMWMiEH3jXYpadWN5vK2Bs9yfnLW8NsPr\n"
      "B/1MiWri3633IdGeT95MvCD+QHQQR3C9KZpwRU1PODE7h19QHgMc0rXWGzX5R+g/\n"
      "+vNsTAuY1cakOMTgWFwY/pWbidXqm2nBAoIBAQCT9eRDA15ssxylfCn9o0kyyTHM\n"
      "y+P1NPvWd0o1akDCBZU47o+DhMPAav7Gs0YAlm3Z8ZMPB3rcbhIFrTdHzmSY74kF\n"
      "s4iLe0cd7eQ9x7N51nEbEYmUzFML8U47oV8A1INuc5PBFmlehKJwagHzXRLw0WTX\n"
      "AmqKQSpEVbqtLvsWVkioqLmfQaKNs74hpAspufj/jigC5654lV0+edwEtkduB/Ju\n"
      "ZTVOusO99rTZUIDAqZb8Wi+1IbQ9+omI7IOCLkTnT/A3Bevj2/nti12GOrXGlD9T\n"
      "4FMOcIyX95fP8LgW5IE4g+6jTp4Qc1b06NTcbRc/MBntVPG+J7Xf8ijnMtQa\n"
      "-----END RSA PRIVATE KEY-----";
    std::unique_ptr<Token> token(Token::Parse(keymaster_token.c_str(), keymaster_token.size()));
    Jwe jwe(private_key.c_str());
    const json_t *header = token->header_claims();

    EXPECT_NE(nullptr, token.get());
    EXPECT_EQ(true, token->IsEncrypted());
    EXPECT_STREQ("RSA1_5", json_string_value(json_object_get(header,"alg")));
    EXPECT_STREQ("A256CBC", json_string_value(json_object_get(header,"enc")));
    EXPECT_EQ(2, json_integer_value(json_object_get(header,"kid")));
    EXPECT_STREQ("K9li/f7Y0t2x6PNQeym3Bg==\n", json_string_value(json_object_get(header,"iv")));
    EXPECT_EQ(true, token->Decrypt(&jwe));
    EXPECT_STREQ("{\"token\":\"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiIsImtpZCI6M30.eyJkZXZpY2VfaWQiOjEwLCJzdWIiOiJkZXZpY2UvMDNhZWVjNTUtNTZlNS00MDViLWE2ODAtYzM1NDMwZjdkZmU1IiwiYXVkIjoiYmluYWNxX3ByaW9yaXR5IiwiaXNzIjoiYmluYWNxX3NpbmsiLCJzZXJ2aWNlX25hbWUiOiJiaW5hY3Ffc2luayIsImNlcnRfaWQiOjMsImlhdCI6MTQzNzAxMTQ4Nn0.Vn6dw00c84PYaryfhJonf-H8FC5lTMPeh1gwdTY-3SZuiW8T8OJmDR05xlkOtPNg3fNWb04r-SYtk19iGRh-eODVVj7O4REaMfpyZTVhEDVakPYYYH_8FW5p2-J5yL11vkD1gzrw73KJfgWSGjReW_NqvTa5ADvpa3bRkIUTfZNLyo0irdddLbmqtOwTwVai7WXHGRh0iaqJDYiuxFPP7ttVWlEornLyVxGrT0G-3NOcQImUQhhyF7r1Y1V6b3zx7__Y-9blsw2WzotdoEEUFtDtyRJDj-Rlus_nRH0yMhrgIuy8kccKnre9baIaMTu3EN22d4kZhafCrYtT7NhURbq8-iwKgBrTp_5ub7kcLX2DB-sfT2CMgC4XDqfqpWIaLIEjUCy5lVNAgt17Gqc6nFD77T04wt7uTBOWjpqquOEaTRTdkf94kfPWz0P7rnX3HFybAq4s6gdFR1GXt08q0xzplocfPRtJEBtU94r_ekd97f9XMjFcCmFQRg0G-XFyvjI5dLXmia1-g6AhLvCBh3Ve3bru8MsznLPXNmxBdGigjmBAJFX9UOqgsR3VPbxpqhhlSBiJL3IJOVB_t0oiTz7Eeew5iORTPMTxYU0_EdPUrhi_mt-RDcc7S1pnWQljJZjo2ArBqQhoSGETujmkITkhQHNjadr2-bIN-OuRLM0\"}",  (char *) token->decrypted());

    json_error_t error;
    json_t* nextToken = json_loads((char*) token->decrypted(), JSON_REJECT_DUPLICATES, &error);

    json_t *innertoken = json_object_get(nextToken, "token");
    const char *tokstr = json_string_value(innertoken);
    std::unique_ptr<Token> parsedInner(Token::Parse(tokstr, strlen(tokstr)));

    EXPECT_NE(nullptr, parsedInner.get());


    std::string pubkey = "-----BEGIN PUBLIC KEY-----\n"
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuVHVSuelwW+xZCvrMg73\n"
            "cms1eAkCd2vz6B+PgLlJ98MGYqwrsaLkJT3RnS4D4lQ/q3U4Z6fT6DLtF+4dltEt\n"
            "pNspcy6arJNYdjjwwirIYoDFzVvLeShnLUJ95X9x9/JapnM7Hne4vEiDrXk/67cW\n"
            "4ETed3Syu9Pc170stoU6GSApIq/vfUPleU+AqDi8USNoLedZNQfzEZUJZj8eLfzb\n"
            "NbgXDXnkHKU38TRv/AWjw5aV4TtF/PlE9eim1Umxmu4e1leR1I27bBlijk37FwEw\n"
            "WqVbr6KAHGbXfL0Y9KY5eddzy7EqTEs5wDhS1MKGx/muge3QA0eKnAkgfU+mLkqv\n"
            "YiTWNOVtTaFy7gmJIK7pNjQZGVqQ0sQD7DGkOs5u3CXE5j4TxmlGg0g2r8i67Xv2\n"
            "7RCeI74vOLVqJHXzXnq/UJQWPIiBvmeUn6EnU/bJhv/2L38KhVk97MzWfAbg7+35\n"
            "oCVgqsWieQAikSZxc1kTOy1eFknmJdzxRb5LH3dFI5YISntzJgg4OyJrzgAqHHYn\n"
            "TpYXBkWkARWXwEHwEIAlHgTurL7dUh4MavVh0pyNidXfr9KPyhfhWQJg4Tle9rq5\n"
            "awQYcgcwYQcxeeN2Hf0qF+PrZDD5hnEvgpfH4r/Xtzm1/bDxj6DFb3is2VqbhgGL\n"
            "zURMHrE6g4CGkyUbActBc88CAwEAAQ==\n"
            "-----END PUBLIC KEY-----";
    RS512Validator validator(pubkey);
    JwsVerifier verifier(&validator);

    EXPECT_EQ(true, parsedInner->VerifySignature(&verifier));
}


