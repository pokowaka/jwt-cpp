#include <string>
#ifndef SRC_INCLUDE_BASE64_H_
#define SRC_INCLUDE_BASE64_H_
class UrlEncode {
 public:
    static std::string encode(const std::string& input);
    static std::string decode(const std::string& input);
    static int decode(const char *in, size_t inLen, char *out, size_t *outLen);
    static int encode(const char* pData, size_t cData, char* result, size_t cResult);

 private:
    static const char s_padCharacter;
    static const char s_encodeLookup[];
    static const char s_decodeLookup[];
};
#endif  // SRC_INCLUDE_BASE64_H_"
