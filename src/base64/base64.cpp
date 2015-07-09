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
#include "base64/base64.h"
#include <string>
#include "util/allocators.h"

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
    uint8_t ch = *decode++;
    char c = decode_table_[ch];

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
          if ((len += 3) > *num_out) {
            return 1; /* buffer overflow */
          }
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
  const uint8_t *data = reinterpret_cast<const uint8_t*>(encode);  // No sign weirdness please..
  size_t resultIndex = 0;
  size_t x;
  uint32_t n = 0;
  uint8_t n0, n1, n2, n3;

  /* increment over the size of the string, three characters at a time */
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

  // No padding as per JWT spec (See section 6)
  result[resultIndex] = 0;
  return 0;   /* indicate success */
}

std::string Base64Encode::EncodeUrl(const std::string &input) {
  size_t num_encoded =  EncodeBytesNeeded(input.size());
  str_ptr encoded(new char[num_encoded]);
  if (EncodeUrl(input.c_str(), input.size(), encoded.get(), num_encoded))
    return "";

  return std::string(encoded.get(), num_encoded);
}

std::string Base64Encode::DecodeUrl(const std::string &input) {
  size_t num_decoded = DecodeBytesNeeded(input.size());
  str_ptr decoded(new char[num_decoded]);
  if (DecodeUrl(input.c_str(), input.size(), decoded.get(), &num_decoded)) {
    return "";
  }
  return std::string(decoded.get(), num_decoded);
}
