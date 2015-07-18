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
#include "token/keymastertoken.h"
#include "util/allocators.h"

Token* KeymasterToken::decrypt_and_verify(const char* token, size_t num_token,
      Jwe* decrypter, JwsVerifier* verifier) {
  std::unique_ptr<Token> outerToken(Token::Parse(token, num_token));
  if (outerToken.get() == NULL) {
    return nullptr;
  }
  if (!outerToken->Decrypt(decrypter)) {
    return nullptr;
  }

  json_error_t error;
  unique_json_ptr decrypted(json_loads(
          const_cast<char*>(reinterpret_cast<const char*>(outerToken->decrypted())),
      JSON_REJECT_DUPLICATES, &error));

  if (decrypted.get() == NULL) {
    return nullptr;
  }
  json_t *innertoken = json_object_get(decrypted.get(), "token");
  if (innertoken == NULL) {
    return nullptr;
  }

  const char *tokstr = json_string_value(innertoken);
  std::unique_ptr<Token> parsedInnerToken(Token::Parse(tokstr, strlen(tokstr)));

  if (parsedInnerToken.get() == NULL || !parsedInnerToken->VerifySignature(verifier)) {
    return nullptr;
  }

  return parsedInnerToken.release();
}

