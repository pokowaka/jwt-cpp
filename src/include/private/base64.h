// Copyright (c) 2015 Erwin Jansen
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#ifndef SRC_INCLUDE_PRIVATE_BASE64_H_
#define SRC_INCLUDE_PRIVATE_BASE64_H_
#include <math.h>
#include <string>

#define INVALID 66

/**
 * A Class that is capable of encoding & decoding base64 that
 * are specific to PRIVATE spec.
 *
 * Basically this means the URL alphabet, and no padding.
 */
class Base64Encode {
public:
  static std::string EncodeUrl(const std::string &input);
  static std::string DecodeUrl(const std::string &input);

  /**
   * Decodes the given base64 encoded string into the out array.
   *
   * @return 0 on success
   */
  static int DecodeUrl(const char *decode, size_t num_decode, char *out,
                       size_t *num_out);
  /**
   * Encodes the given array of bytes into the pre allocated array.
   *
   * @return 0 on success
   */
  static int EncodeUrl(const char *encode, size_t num_encode, char *result,
                       size_t *num_result);

  /**
   * Checks if this is a valid char in the base64 url set
   *
   * @return true if it is a valid char
   */
  inline static bool IsValidBase64Char(const char ch) {
    return DecodeChar(ch) != INVALID;
  }

  /**
   * Gets the number of bytes needed to decode a base64 encoded string of the
   * given size
   * @param num_decode length of the string you wish to decode
   * @return the number of bytes encoded in this string
   */
  inline static size_t DecodeBytesNeeded(size_t num_decode) {
    return 3 + (num_decode / 4) * 3;
  }

  /**
   * Gets the number of chars needed to encode the given number
   * of bytes in base64
   * @param num_encode the number of bytes you wish to encode
   * @return the number of bytes encoded in this string
   */
  inline static size_t EncodeBytesNeeded(size_t num_encode) {
    // Well, the spec calls out to not add padding..
    int left = num_encode - ((num_encode / 3) * 3);
    int sub = left == 1 ? 2 : (left == 2 ? 1 : 0);
    return 4 * ceil(static_cast<float>(num_encode) / 3) + 1 - sub;
  }

private:
  inline static char DecodeChar(uint8_t in) {
    const char table[] = {
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 62, 66, 62, 66, 63, 52, 53, 54, 55, 56, 57,
        58, 59, 60, 61, 66, 66, 66, 66, 66, 66, 66, 0,  1,  2,  3,  4,  5,  6,
        7,  8,  9,  10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 66, 66, 66, 66, 63, 66, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
        37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
        66, 66, 66, 66};
    return table[in];
  }

  inline static char EncodeChar(uint8_t in);
};
#endif // SRC_INCLUDE_PRIVATE_BASE64_H_
