#include "base64.h"
#include <inttypes.h>
#include <string.h>
#include <string>
#include <memory>

#define WHITESPACE 64
#define EQUALS     65
#define INVALID    66

// Lookup table for encoding
// If you want to use an alternate alphabet, change the characters here
const char UrlEncode::s_encodeLookup[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const char UrlEncode::s_padCharacter = '=';
const char UrlEncode::s_decodeLookup[] = {
  66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 64, 66, 66, 66, 66,
  66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66,
  66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 62, 66,
  62, 66, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 66, 66,
  66, 65, 66, 66, 66,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
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
  66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66, 66 };

int UrlEncode::decode(const char *in, size_t inLen, char *out, size_t *outLen) {
  const char *end = in + inLen;
  char iter = 0;
  size_t buf = 0, len = 0;

  while (in < end) {
    char c = s_decodeLookup[*in++];

    switch (c) {
      case WHITESPACE: return 1;   /* skip whitespace */
      case INVALID:    return 1;   /* invalid input, return error */
      case EQUALS:     in = end;   /* pad character, end of data */
                       continue;
      default:
                       buf = buf << 6 | c;
                       iter++;   // increment the number of iteration
                       /* If the buffer is full, split it into bytes */
                       if (iter == 4) {
                         if ((len += 3) > *outLen) return 1; /* buffer overflow */
                         *(out++) = (buf >> 16) & 255;
                         *(out++) = (buf >> 8) & 255;
                         *(out++) = buf & 255;
                         buf = 0; iter = 0;
                       }
    }
  }

  if (iter == 3) {
    if ((len += 2) > *outLen) {
      return 1; /* buffer overflow */
    }
    *(out++) = (buf >> 10) & 255;
    *(out++) = (buf >> 2) & 255;
  } else {
    if (iter == 2) {
      if (++len > *outLen) {
        return 1; /* buffer overflow */
      }
      *(out++) = (buf >> 4) & 255;
    }
  }

  *outLen = len; /* modify to reflect the actual output size */
  return 0;
}

int UrlEncode::encode(const char* pData, size_t cData, char* result, size_t cResult) {
  const char *data = (const char *)pData;
  size_t resultIndex = 0;
  size_t x;
  uint32_t n = 0;
  int padCount = cData % 3;
  char n0, n1, n2, n3;

  /* increment over the length of the string, three characters at a time */
  for (x = 0; x < cData; x += 3) {
    /* these three 8-bit (ASCII) characters become one 24-bit number */
    n = static_cast<uint32_t>(data[x]) << 16;

    if ((x+1) < cData) {
      n += static_cast<uint32_t>(data[x+1]) << 8;
    }

    if ((x+2) < cData) {
      n += data[x+2];
    }

    /* this 24-bit number gets separated into four 6-bit numbers */
    n0 = static_cast<char>((n >> 18) & 63);
    n1 = static_cast<char>((n >> 12) & 63);
    n2 = static_cast<char>((n >> 6) & 63);
    n3 = static_cast<char>(n & 63);

    /*
     * if we have one byte available, then its encoding is spread
     * out over two characters
     */
    if (resultIndex >= cResult) {
      return 1;   /* indicate failure: buffer too small */
    }
    result[resultIndex++] = s_encodeLookup[n0];
    if (resultIndex >= cResult) {
      return 1;   /* indicate failure: buffer too small */
    }
    result[resultIndex++] = s_encodeLookup[n1];

    /*
     * if we have only two bytes available, then their encoding is
     * spread out over three chars
     */
    if ((x+1) < cData) {
      if (resultIndex >= cResult) {
        return 1;   /* indicate failure: buffer too small */
      }
      result[resultIndex++] = s_encodeLookup[n2];
    }

    /*
     * if we have all three bytes available, then their encoding is spread
     * out over four characters
     */
    if ((x+2) < cData) {
      if (resultIndex >= cResult) return 1;   /* indicate failure: buffer too small */
      result[resultIndex++] = s_encodeLookup[n3];
    }
  }

  /*
   * create and add padding that is required if we did not have a multiple of 3
   * number of characters available
   */
  if (padCount > 0) {
    for (; padCount < 3; padCount++) {
      if (resultIndex >= cResult) {
        return 1;   /* indicate failure: buffer too small */
      }
      result[resultIndex++] = s_padCharacter;
    }
  }
  if (resultIndex >= cResult) {
    return 1;   /* indicate failure: buffer too small */
  }
  result[resultIndex] = 0;
  return 0;   /* indicate success */
}

std::string UrlEncode::encode(const std::string& strInput) {
  size_t cStrEncoded = 1 + (((strInput.size()/3) + (strInput.size() % 3 > 0)) * 4);
  std::string strEncoded;
  strEncoded.reserve(cStrEncoded);
  int res = encode(strInput.c_str(), strInput.size(),
      const_cast<char*>(strEncoded.c_str()), cStrEncoded);

  if (res)
    return "";

  return strEncoded;
}

std::string UrlEncode::decode(const std::string& strInput) {
  size_t padding = 0;
  if (strInput.length()) {
    if (strInput[strInput.length()-1] == s_padCharacter)
      padding++;
    if (strInput[strInput.length()-2] == s_padCharacter)
      padding++;
  }
  size_t cStrDecoded = ((strInput.length()/4)*3) - padding;
  std::string strDecoded;
  strDecoded.resize(cStrDecoded);
  int res = decode(strInput.c_str(), strInput.size(),
      const_cast<char*>(strDecoded.c_str()), &cStrDecoded);
  if (res)
    return "";

  return strDecoded;
}
