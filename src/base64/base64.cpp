#include "base64.h"

#define WHITESPACE 64
#define EQUALS     65
#define INVALID    66


// Implementations from
// https://en.wikibooks.org/wiki/Algorithm_Implementation/Miscellaneous/Base64

// Lookup table for encoding
// If you want to use an alternate alphabet, change the characters here
const char Base64Encode::encode_table_[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const char Base64Encode::pad_char_ = '=';
const char Base64Encode::decode_table_[] = {
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 64, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 62, 66,
        62, 66, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 66, 66,
        66, 65, 66, 66, 66, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 66, 66, 66, 66, 63, 66, 26, 27, 28, 29, 30, 31, 32, 33,
        34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
        49, 50, 51, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66};

int Base64Encode::DecodeUrl(const char *decode, size_t num_decode, char *out, size_t *num_out) {
    const char *end = decode + num_decode;
    char iter = 0;
    size_t buf = 0, len = 0;

    while (decode < end) {
        char c = decode_table_[*decode++];

        switch (c) {
            case WHITESPACE:
                return 1;   /* skip whitespace */
            case INVALID:
                return 1;   /* invalid input, return error */
            case EQUALS:
                decode = end;   /* pad character, end of data */
                continue;
            default:
                buf = buf << 6 | c;
                iter++;   // increment the number of iteration
                /* If the buffer is full, split it into bytes */
                if (iter == 4) {
                    if ((len += 3) > *num_out) return 1; /* buffer overflow */
                    *(out++) = (buf >> 16) & 255;
                    *(out++) = (buf >> 8) & 255;
                    *(out++) = buf & 255;
                    buf = 0;
                    iter = 0;
                }
        }
    }

    if (iter == 3) {
        if ((len += 2) > *num_out) {
            return 1; /* buffer overflow */
        }
        *(out++) = (buf >> 10) & 255;
        *(out++) = (buf >> 2) & 255;
    } else {
        if (iter == 2) {
            if (++len > *num_out) {
                return 1; /* buffer overflow */
            }
            *(out++) = (buf >> 4) & 255;
        }
    }

    *num_out = len; /* modify to reflect the actual output size */
    return 0;
}

int Base64Encode::EncodeUrl(const char *encode, size_t num_encode, char *result, size_t num_result) {
    const char *data = encode;
    size_t resultIndex = 0;
    size_t x;
    uint32_t n = 0;
    int padCount = num_encode % 3;
    uint8_t n0, n1, n2, n3;

    /* increment over the length of the string, three characters at a time */
    for (x = 0; x < num_encode; x += 3) {
        /* these three 8-bit (ASCII) characters become one 24-bit number */
        n = static_cast<uint32_t>(data[x]) << 16;

        if ((x + 1) < num_encode) {
            n += static_cast<uint32_t>(data[x + 1]) << 8;
        }

        if ((x + 2) < num_encode) {
            n += data[x + 2];
        }

        /* this 24-bit number gets separated into four 6-bit numbers */
        n0 = static_cast<uint8_t>((n >> 18) & 63);
        n1 = static_cast<uint8_t>((n >> 12) & 63);
        n2 = static_cast<uint8_t>((n >> 6) & 63);
        n3 = static_cast<uint8_t>(n & 63);

        /*
         * if we have one byte available, then its encoding is spread
         * out over two characters
         */
        if (resultIndex >= num_result) {
            return 1;   /* indicate failure: buffer too small */
        }
        result[resultIndex++] = encode_table_[n0];
        if (resultIndex >= num_result) {
            return 1;   /* indicate failure: buffer too small */
        }
        result[resultIndex++] = encode_table_[n1];

        /*
         * if we have only two bytes available, then their encoding is
         * spread out over three chars
         */
        if ((x + 1) < num_encode) {
            if (resultIndex >= num_result) {
                return 1;   /* indicate failure: buffer too small */
            }
            result[resultIndex++] = encode_table_[n2];
        }

        /*
         * if we have all three bytes available, then their encoding is spread
         * out over four characters
         */
        if ((x + 2) < num_encode) {
            if (resultIndex >= num_result) return 1;   /* indicate failure: buffer too small */
            result[resultIndex++] = encode_table_[n3];
        }
    }

    /*
     * create and add padding that is required if we did not have a multiple of 3
     * number of characters available
     */
    if (padCount > 0) {
        for (; padCount < 3; padCount++) {
            if (resultIndex >= num_result) {
                return 1;   /* indicate failure: buffer too small */
            }
            result[resultIndex++] = pad_char_;
        }
    }
    if (resultIndex >= num_result) {
        return 1;   /* indicate failure: buffer too small */
    }
    result[resultIndex] = 0;
    return 0;   /* indicate success */
}

std::string Base64Encode::EncodeUrl(const std::string &input) {
    size_t num_encoded = 1 + (((input.size() / 3) + (input.size() % 3 > 0)) * 4);
    std::unique_ptr<char> encoded(new char[num_encoded]);
    if (EncodeUrl(input.c_str(), input.size(), encoded.get(), num_encoded))
        return "";

    return std::string(encoded.get(), num_encoded);
}

std::string Base64Encode::DecodeUrl(const std::string &input) {
    size_t padding = 0;
    if (input.length()) {
        if (input[input.length() - 1] == pad_char_)
            padding++;
        if (input[input.length() - 2] == pad_char_)
            padding++;
    }
    size_t num_decoded = ((input.length() / 4) * 3) - padding;
    std::unique_ptr<char> decoded(new char[num_decoded]);
    if (DecodeUrl(input.c_str(), input.size(), decoded.get(), &num_decoded))
        return "";

    return std::string(decoded.get(), num_decoded);
}
