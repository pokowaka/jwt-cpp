#include "base64.h"
#include "gtest/gtest.h"

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
    std::string expectedResult = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZyBhbmQgc29tZSBleHRy";
    EXPECT_STREQ(expectedResult.c_str(), UrlEncode::encode(inputData).c_str());
    EXPECT_STREQ(inputData.c_str(), UrlEncode::decode(expectedResult).c_str());
}

TEST(base64_test, spec) {
    EXPECT_STREQ("" , UrlEncode::decode("").c_str());
    EXPECT_STREQ("f" , UrlEncode::decode("Zg==").c_str());
    EXPECT_STREQ("fo" , UrlEncode::decode("Zm8=").c_str());
    EXPECT_STREQ("foo" , UrlEncode::decode("Zm9v").c_str());
    EXPECT_STREQ("foob" , UrlEncode::decode("Zm9vYg==").c_str());
    EXPECT_STREQ("fooba" , UrlEncode::decode("Zm9vYmE=").c_str());
    EXPECT_STREQ("foobar" , UrlEncode::decode("Zm9vYmFy").c_str());
}

TEST(base64_test, spec_inv) {
    EXPECT_STREQ("", UrlEncode::encode("").c_str());
    EXPECT_STREQ("Zg==", UrlEncode::encode("f") .c_str());
    EXPECT_STREQ("Zm8=", UrlEncode::encode("fo") .c_str());
    EXPECT_STREQ("Zm9v", UrlEncode::encode("foo").c_str());
    EXPECT_STREQ("Zm9vYg==", UrlEncode::encode("foob").c_str());
    EXPECT_STREQ("Zm9vYmE=", UrlEncode::encode("fooba").c_str());
    EXPECT_STREQ("Zm9vYmFy", UrlEncode::encode("foobar").c_str());
}

TEST(base64_test, bad) {
    EXPECT_STREQ("", UrlEncode::decode("Zg ==").c_str());
    EXPECT_STREQ("", UrlEncode::decode("Zg =").c_str());
    EXPECT_STREQ("", UrlEncode::decode("Zm9vYmE@").c_str());
    EXPECT_STREQ("", UrlEncode::decode("VGhlIHF1aWNrIGJy\nb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZyBhbmQgc29tZSBleHR").c_str());
}

TEST(base64_test, random) {
    char res[4096];
    char dec[4096];
    for(int i = 0; i < 10000; i++) {
        uint32_t fst =  random();
        uint32_t snd = random();
        std::string input = combine(fst, snd);
        size_t cOut = 1 +  ((input.size()/3) + (input.size() % 3 > 0)) * 4;
        size_t cRes = 4096;
        UrlEncode::encode(input.c_str(), input.size(), res, 4096);
        UrlEncode::decode(res, cOut, dec, &cRes);
        ASSERT_STREQ(input.c_str(), dec);
    }
}

TEST(base64_test, perf_encode_c) {
    // encode = 'Send reinforcements'
    // Benchmark.measure{  50_000_000.times { Base64.encode64(encode) } }
    // => #<Benchmark::Tms:0x71a8adcf @stime=0.120000000000001, @label="", @cstime=0.0, @real=22.494999885559082, @total=23.19, @cutime=0.0, @utime=23.07>
    // vs: base64_test.perf (2186 ms) (10x faster than ruby)
    std::string encode = "Send reinforcements";
    char res[4096];
    for(int i = 0; i < 5000000; i++) {
        UrlEncode::encode(encode.c_str(), encode.size(), res, 4096);
    }
}

TEST(base64_test, perf_encode_cplus) {
    // encode = 'Send reinforcements'
    // Benchmark.measure{  5_000_000.times { Base64.encode64(encode) } }
    //  => #<Benchmark::Tms:0x4310d43 @stime=0.00999999999999801, @label="", @cstime=0.0, @real=2.2860000133514404, @total=2.329999999999991, @cutime=0.0, @utime=2.319999999999993>
    // vs: base64_test.perf (227 ms) (10x faster than ruby)
    std::string encode = "Send reinforcements";
    for(int i = 0; i < 5000000; i++) {
        UrlEncode::encode(encode);
    }
}

TEST(base64_test, perf_decode_c) {
    //#<Benchmark::Tms:0x47d9a273 @stime=0.010000000000001563, @label="", @cstime=0.0, @real=1.4619998931884766, @total=1.5199999999999925, @cutime=0.0, @utime=1.509999999999991>
    //vs 328ms (5x faster).
    std::string encode = "U2VuZCByZWluZm9yY2VtZW50cw==";
    char res[4096];
    size_t cRes = 4096;
    for(int i = 0; i < 5000000; i++) {
        UrlEncode::decode(encode.c_str(), encode.size(), res, &cRes);
    }
}

TEST(base64_test, perf_decode_cplus) {
    std::string encode = "U2VuZCByZWluZm9yY2VtZW50cw==";
    for(int i = 0; i < 5000000; i++) {
        UrlEncode::decode(encode);
    }
}
