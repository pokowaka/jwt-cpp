#include "private/base64.h"
#include "gtest/gtest.h"

#define MANY_TIMES 5000

std::string combine(uint32_t fst, uint32_t snd) {
    std::string res;
    res.reserve(8);
    res.append(1, fst & 0xFF);
    res.append(1, fst & 0xFF00);
    res.append(1, fst & 0xFF0000);
    res.append(1, fst & 0xFF000000);
    res.append(1, snd & 0xFF);
    res.append(1, snd & 0xFF00);
    res.append(1, snd & 0xFF0000);
    res.append(1, snd & 0xFF000000);
    return res;
}

TEST(base64_test,  quick_fox) {
    std::string inputData = "The quick brown fox jumps over the lazy dog and some extr";
    std::string expectedResult =
      "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZyBhbmQgc29tZSBleHRy";
    EXPECT_STREQ(expectedResult.c_str(), Base64Encode::EncodeUrl(inputData).c_str());
    EXPECT_STREQ(inputData.c_str(), Base64Encode::DecodeUrl(expectedResult).c_str());
}

TEST(base64_test, buffer_overflows) {
  std::string str_dec =
    "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZyBhbmQgc29tZSBleHRy";
  char buffer[4096];

  for (size_t num_dec = 6; num_dec < str_dec.size(); num_dec++) {
    for (size_t num_buffer = 0;
        num_buffer < Base64Encode::DecodeBytesNeeded(num_dec) / 2 ; num_buffer++) {
      EXPECT_EQ(1, Base64Encode::DecodeUrl(str_dec.c_str(), num_dec, buffer, &num_buffer));
    }
  }
}

TEST(base64_test, buffer_underflows) {
  std::string str_enc = "The quick brown fox jumps over the lazy dog and some extr";
  char buffer[4096];

  for (size_t num_enc = 6; num_enc < str_enc.size(); num_enc++) {
    for (size_t num_buffer = 0;
        num_buffer < Base64Encode::EncodeBytesNeeded(num_enc) / 2; num_buffer++) {
      EXPECT_EQ(1, Base64Encode::EncodeUrl(str_enc.c_str(), num_enc, buffer, &num_buffer));
    }
  }
}

TEST(base64_test, partial) {
  const char* foobar = "Zm9vYmFy";
  char buf[] = {0, 0, 0, 0, 0, 0, 0, 0 };
  size_t cBuf = 8;
  Base64Encode::DecodeUrl(foobar, 4, buf, &cBuf);
  EXPECT_EQ(3, cBuf);
  EXPECT_STREQ("foo", buf);
}

TEST(base64_test, len) {
  std::string hello;
  for (int i = 0; i < 9; i++) {
    hello.append("x");
    std::string enc = Base64Encode::EncodeUrl(hello);
    EXPECT_EQ(enc.size(), Base64Encode::EncodeBytesNeeded(hello.size()));
  }
}

TEST(base64_test, spec) {
    EXPECT_STREQ("" , Base64Encode::DecodeUrl("").c_str());
    EXPECT_STREQ("f" , Base64Encode::DecodeUrl("Zg").c_str());
    EXPECT_STREQ("fo" , Base64Encode::DecodeUrl("Zm8").c_str());
    EXPECT_STREQ("foo" , Base64Encode::DecodeUrl("Zm9v").c_str());
    EXPECT_STREQ("foob" , Base64Encode::DecodeUrl("Zm9vYg").c_str());
    EXPECT_STREQ("fooba" , Base64Encode::DecodeUrl("Zm9vYmE").c_str());
    EXPECT_STREQ("foobar" , Base64Encode::DecodeUrl("Zm9vYmFy").c_str());
}

TEST(base64_test, spec_inv) {
  // Note! No padding for JWT Base 64
    EXPECT_STREQ("", Base64Encode::EncodeUrl("").c_str());
    EXPECT_STREQ("Zg", Base64Encode::EncodeUrl("f") .c_str());
    EXPECT_STREQ("Zm8", Base64Encode::EncodeUrl("fo") .c_str());
    EXPECT_STREQ("Zm9v", Base64Encode::EncodeUrl("foo").c_str());
    EXPECT_STREQ("Zm9vYg", Base64Encode::EncodeUrl("foob").c_str());
    EXPECT_STREQ("Zm9vYmE", Base64Encode::EncodeUrl("fooba").c_str());
    EXPECT_STREQ("Zm9vYmFy", Base64Encode::EncodeUrl("foobar").c_str());
}

TEST(base64_test, bad) {
    EXPECT_STREQ("", Base64Encode::DecodeUrl("Zg ==").c_str());
    EXPECT_STREQ("", Base64Encode::DecodeUrl("Zg =").c_str());
    EXPECT_STREQ("", Base64Encode::DecodeUrl("Zm9vYmE@").c_str());
    EXPECT_STREQ("", Base64Encode::DecodeUrl(
            "VGhlIHF1aWNrIGJy\n"
            "b3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZyBhbmQgc29tZSBleHR").c_str());
}

TEST(base64_test, invers) {
  std::string res = "dCm-Fpm5S8VCg0Mi8LPdMNwrZhQWtox7hFsH6oG-yf4";
  std::string out = Base64Encode::DecodeUrl(res);
  ASSERT_EQ(32, out.size());
  ASSERT_STREQ(res.c_str(), Base64Encode::EncodeUrl(Base64Encode::DecodeUrl(res)).c_str());
}

TEST(base64_test, random) {
    size_t buf = 4096;
    char res[4096];
    char dec[4096];
    for (int i = 0; i < 10000; i++) {
        uint32_t fst =  random();
        uint32_t snd = random();
        std::string input = combine(fst, snd);
        size_t cOut = 1 +  ((input.size()/3) + (input.size() % 3 > 0)) * 4;
        size_t cRes = 4096;
        Base64Encode::EncodeUrl(input.c_str(), input.size(), res, &buf);
        Base64Encode::DecodeUrl(res, cOut, dec, &cRes);
        ASSERT_STREQ(input.c_str(), dec);
    }
}

TEST(base64_test, perf_encode_c) {
    // EncodeUrl = 'Send reinforcements'
    // Benchmark.measure{  50_000_000.times { Base64.encode64(EncodeUrl) } }
    // => #<Benchmark::Tms:0x71a8adcf @stime=0.120000000000001,
    // @label="", @cstime=0.0, @real=22.494999885559082, @total=23.19, @cutime=0.0, @utime=23.07>
    // vs: base64_test.perf (2186 ms) (10x faster than ruby)
    std::string encode = "Send reinforcements";
    size_t buf = 4096;
    char res[4096];
    for (int i = 0; i < MANY_TIMES; i++) {
        Base64Encode::EncodeUrl(encode.c_str(), encode.size(), res, &buf);
    }
}

TEST(base64_test, perf_encode_cplus) {
    // EncodeUrl = 'Send reinforcements'
    // Benchmark.measure{  5_000_000.times { Base64.encode64(EncodeUrl) } }
    //  => #<Benchmark::Tms:0x4310d43 @stime=0.00999999999999801, @label="", @cstime=0.0, @real=2.2860000133514404, @total=2.329999999999991, @cutime=0.0, @utime=2.319999999999993>
    // vs: base64_test.perf (227 ms) (10x faster than ruby)
    std::string encode = "Send reinforcements";
    for (int i = 0; i < MANY_TIMES; i++) {
        Base64Encode::EncodeUrl(encode);
    }
}

TEST(base64_test, perf_decode_c) {
    //#<Benchmark::Tms:0x47d9a273 @stime=0.010000000000001563, @label="", @cstime=0.0, @real=1.4619998931884766, @total=1.5199999999999925, @cutime=0.0, @utime=1.509999999999991>
    //vs 328ms (5x faster).
    std::string encode = "U2VuZCByZWluZm9yY2VtZW50cw==";
    char res[4096];
    size_t cRes = 4096;
    for(int i = 0; i < MANY_TIMES; i++) {
        Base64Encode::DecodeUrl(encode.c_str(), encode.size(), res, &cRes);
    }
}

TEST(base64_test, perf_decode_cplus) {
    std::string encode = "U2VuZCByZWluZm9yY2VtZW50cw==";
    for(int i = 0; i < MANY_TIMES; i++) {
        Base64Encode::DecodeUrl(encode);
    }
}
