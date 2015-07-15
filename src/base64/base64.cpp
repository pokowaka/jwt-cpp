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

inline char Base64Encode::EncodeChar(uint8_t in) {
  const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  return table[in];
}

inline char Base64Encode::DecodeChar(uint8_t in) {
  const char table[] = {
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
  return table[in];
}


int Base64Encode::DecodeUrl(const char *decode, size_t num_decode, char *out, size_t *num_out) {
  if (*num_out < DecodeBytesNeeded(num_decode))
    return 1;

  const char *end = decode + num_decode;
  const char *out_start = out;
  char iter = 0;
  uint32_t buf = 0;

  while (decode < end) {
    uint8_t ch = *decode++;
    char c = DecodeChar(ch);

    switch (c) {
      case WHITESPACE:
        return 1;   // skip whitespace
      case INVALID:
        return 1;   // invalid input, return error
      case EQUALS:
        decode = end;   // pad character, end of data
        continue;
      default:
        buf = buf << 6 | c;
        iter++;   // increment the number of iteration
        // If the buffer is full, split it into bytes
        if (iter == 4) {
          *(out++) = (buf >> 16) & 0xff;
          *(out++) = (buf >> 8) & 0xff;
          *(out++) = buf & 0xff;
          buf = 0;
          iter = 0;
        }
    }
  }

  if (iter == 3) {
    *(out++) = (buf >> 10) & 0xff;
    *(out++) = (buf >> 2) & 0xff;
  } else {
    if (iter == 2) {
      *(out++) = (buf >> 4) & 0xff;
    }
  }

  *num_out = (out - out_start);  // modify to reflect the actual output size
  return 0;
}

int Base64Encode::EncodeUrl(const char* encode, size_t num_encode, char* result, size_t num_result) {
  if (EncodeBytesNeeded(num_encode) > num_result)
    return 1;

  if (num_encode == 0) {
    *result = 0;
    return 0;
  }

  size_t eLen = (num_encode / 3) * 3;                              // Length of even 24-bits.

  // Encode even 24-bits
  for (size_t s = 0; s < eLen; s += 3) {
    // Copy next three bytes into lower 24 bits of int, paying attension to sign.
    uint32_t i = (*encode++ & 0xff) << 16;
    i = i | (*encode++ & 0xff) << 8;
    i = i | (*encode++ & 0xff);

    // Encode the int into four chars
    *result++ =  EncodeChar((i >> 18) & 0x3f);
    *result++ =  EncodeChar((i >> 12) & 0x3f);
    *result++ =  EncodeChar((i >> 6) & 0x3f);
    *result++ =  EncodeChar(i & 0x3f);
  }

  // Pad and encode last bits if source isn't an even 24 bits.
  size_t left = num_encode - eLen;   // 0 - 2.
  if (left > 0) {
    // Prepare the int
    uint32_t i = ((*encode++ & 0xff) << 10);
    i = i | (left == 2 ? ((*encode & 0xff) << 2) : 0);

    // Set last four chars
    *result++ = EncodeChar(i >> 12);
    *result++ = EncodeChar((i >> 6) & 0x3f);
    *result++ = left == 2 ? EncodeChar(i & 0x3f) : 0;
  }

  *result++ = 0;
  return 0;
}

std::string Base64Encode::EncodeUrl(const std::string &input) {
  size_t num_encoded =  EncodeBytesNeeded(input.size());
  str_ptr encoded(new char[num_encoded]);
  // Impossible to get a buffer overlow
  EncodeUrl(input.c_str(), input.size(), encoded.get(), num_encoded);
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
