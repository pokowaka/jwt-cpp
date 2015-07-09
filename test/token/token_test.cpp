#include <validators/listclaimvalidator.h>
#include "gtest/gtest.h"
#include "token/token.h"
#include "validators/digestvalidator.h"
#include "util/allocators.h"
#include <jansson.h>
#include "token/jwsverifier.h"

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
    json_t *header = token->header_claims();

    EXPECT_NE(nullptr, token);
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
  EXPECT_EQ(true, token->VerifySignature(verifier));
}

TEST(token_test, signed) {
    std::string tokenstr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
    std::unique_ptr<Token> token(Token::Parse(tokenstr.c_str(), tokenstr.size()));
    HS256Validator validator("secret");
    JwsVerifier verifier(&validator);

    const char* const accepted[] = { "1234567890", "bar" };
    SubValidator sub(accepted, 2);

    EXPECT_EQ(true, token->VerifySignature(verifier));
    EXPECT_EQ(true, token->VerifyClaims(sub));
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
    std::string tokenstr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
    HS256Validator validator("secret");
    JwsVerifier verifier(&validator);

    for (int i = 0; i < 5; i++) {
        std::unique_ptr<Token> token(Token::Parse(tokenstr.c_str(), tokenstr.size()));
        EXPECT_EQ(true, token->VerifySignature(verifier));
        EXPECT_NE(nullptr, token->payload_claims());
    }
}


TEST(token_test, keymaster_token) {
    std::string keymaster_token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDIiwiaXYiOiJ2TTFza0luWTF2NG9Va0Fleng4S3JRPT1cbiIsImtpZCI6NDJ9.fCl1Cudbs-td33KZEKP0HtudEik7o9sbMYi1RsAXwn7-AXCeMw-G4RRBAV9se_haUoeJVuXhgAkodLcAv9DNQfPWghaxBdi1JupBhp8jSbrnc58kOOCro5Cmqu6-gk578QuNjwEBSZbQ7AmV67SFXcn3qr1LEgCMdF9Yl1U1Ae4gLh5iwQOwhcp50p6PQveFfPBX9Sdtnsb0nL_jGUySDyGuxesBR1KhC68_a6mioOwOipQBOTGWNffFDYEjDVK0n4BD8bwNX4x80Wp48wn0UQyZuefLCXT-MYyZd84xnJnzwlAq97N0vfC2-GS_H0ECzO4Byzw7_EX5D2JmI5v7WSxqNs0rMSZsZ_hLvc_h8BBz8xghOrwNgKB8_jMn4tl4Oj8UMjhnuuafz9CZ6t5nL8g8Lkr1JZfKEz2u5uR1YAx1DL0ysZEhieSfk1C0qAUzC40EX7Hqzxi4kTMuNiHMpm6t0Gfp92l4XMAsJuA_0VasvQu3e8zUeoFfp9WqRfkvE5vYoC-rgUjsYUvOp4Pe9n_sqCuK14wdKpjzc6YsaSKyHYwyDiW3pwOUv2mC83vf9Q0DdgfnM9A3DaB8MLZ-a7YllU5e4YHVvTVPaI-cPfuog_2aKldyOkBPv0xYro7yFiLTVOtGejpvyykhYdqZoLEijTJ2rA_DQHVFshxqZoU.CIzQl_Hvgk9ysbqMzCzQhyT-vLqMJAbGLcp4aJAOEEY-USo6aelwG20koFYE9oHJQ_Fq9-5-MJA-eXTR12TttRMlJNykaQLnYNVCi0ixR-AzwUb6qfcaQXikjRDWhQORlNjpooNF8z6GEXQSp2M-cHq3B7YBEAwtt3xDx6innuDFCwlVhar8Bc0MYa-9yo40wd4oobiimtScrItA85aNodvVMxq7dbeRYMR9Q-n9Cd_lE__bXDYTaLVQlfCCAZCTxzHC-KTrcRsCEObTFwV-qjXq94eGwrdl-c80gZwsAUkbxvAgoYOqE71OmssHMSpxG2r3GeOnhnivJZKE9rXh66iyX0MEcGQrt0mm4q8NNlFe4IGa2a17Ms3m2CennSBbjXLoiGMY3TV3R3E48V3fSh5nRzQelxg0wTKtiyfQw2jhwibtItoIKJ3KYNZ9rYY2xOtm4YDiERaVe3Jwh8L0smeP0HGBxD8mSFSmp-6nDBvzTv9m_Hx-NL2ieHG4KJHUc_faA5JtM9xxDfUuRGWBBhmaG-ID9mSmB5QV65PyBIPXw3t_B_0uRVKaxLbjTzf7wALhOTqeJ6GsYLFVIAvwePVi7cbDsjkN6eGc2JlgslaOAyHZ1UE-TgEsJ7LiZrFZ9MMjs5tAhPsbe7AFGdgWDia1_ULLVnfvVm8XgQTdMJwikD9AFFWKjuPcbzXLJZJzzMk485nz23Yy0IYpanArzdvPd97qfRahw4zAQQnUrIyy5ILiFlRn15IFAzALzczTctCufxe4Sj-8gN0Ynnb3jF9ho4B3yP6ATbKR3Eh37gBmnfmiRvgXvisFFwve-lMivT4GMYQ6-JPZu7hPIk1sW9fUWA0zeNqdAVZdgCvimtNLGqFvQU7UZIc7ynUcTkArzbafnIx_UX-hvH7TRXKavfH6Sl8cMNdXNQa2-BqhlHD_w0R2NftVQTI_CY1cDijGtIy3oUsvGUE0UM3gBkmkJFSfSaBQI04eqevw5bgG-TDOSEucY5vVy1QtdZ449vsXdr3S9PAA7JDkWS5TPbnVGWD0HxwAC7gw-9juGZ9oS6v2jzG4yB3oZqK1Y80exXxaSA4tndNnmimoDYpjubVvVpoPZhGvZryC5q75oqEVvAi7wvllbWDpM920FXxTiekHEVoZVVIkZssd4PQ4FUs0HNtV02CmGOiFEVsbFuU56xtf0dFsCCZ8IFqwtaagceCUORD7EhVRTmELMgXC5kcIWdbPFoIK6VCghC7qZj2uceZ5iyfTBFhpFu8faFYvMotc9ak-z3tzkWMT74nQbfY6dA";
    std::unique_ptr<Token> token(Token::Parse(keymaster_token.c_str(), keymaster_token.size()));
    json_t *header = token->header_claims();

    EXPECT_NE(nullptr, token);
    EXPECT_EQ(true, token->IsEncrypted());
    EXPECT_STREQ("RSA1_5", json_string_value(json_object_get(header,"alg")));
    EXPECT_STREQ("A256CBC", json_string_value(json_object_get(header,"enc")));
    EXPECT_EQ(42, json_integer_value(json_object_get(header,"kid")));
    EXPECT_STREQ("vM1skInY1v4oUkAezx8KrQ==\n", json_string_value(json_object_get(header,"iv")));
}
