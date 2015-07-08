#include <string>

#ifndef BASE64_BASE64_H_
#define BASE64_BASE64_H_

/**
 * A Class that is capable of encoding & decoding base64 using the
 * url alphabet.
 *
 */
class Base64Encode {
public:
    static std::string EncodeUrl(const std::string &input);

    static std::string DecodeUrl(const std::string &input);

    // Note, these are significantly faster than the std:: version!
    static int DecodeUrl(const char *decode, size_t num_decode, char *out, size_t *num_out);

    static int EncodeUrl(const char *encode, size_t num_encode, char *result, size_t num_result);

private:
    static const char pad_char_;
    static const char encode_table_[];
    static const char decode_table_[];
};

#endif  // BASE64_BASE64_H_
