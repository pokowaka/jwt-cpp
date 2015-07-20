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
#ifndef SRC_VALIDATORS_MESSAGEVALIDATORFACTORY_H_
#define SRC_VALIDATORS_MESSAGEVALIDATORFACTORY_H_

#include <jansson.h>
#include <exception>
#include <string>
#include <vector>
#include "validators/messagevalidator.h"
#include "validators/kidvalidator.h"

class MessageValidatorFactory {
 public:
  static MessageValidator *build(std::string fromJson);
  ~MessageValidatorFactory();

 private:
  std::vector<std::string> buildlist(json_t *lst);
  std::vector<MessageValidator*> buildvalidatorlist(json_t *json);
  std::string ParseSecret(const char *property, json_t *object);
  MessageValidator *build(json_t *fromJson);
  MessageValidator *buildkid(KidValidator* kid, json_t *kidlist);

  std::vector<MessageValidator*> build_;
};

class ParsedMessagevalidator : public MessageValidator {
 public:
  ParsedMessagevalidator(json_t *json, const std::vector<MessageValidator*> &children,
      MessageValidator *root);
  ~ParsedMessagevalidator();

  bool Verify(json_t *jsonHeader, const uint8_t *header, size_t num_header,
              const uint8_t *signature, size_t num_signature) override;
  const char *algorithm() const override;
  bool Accepts(const char* algorithm) const override;
  std::string toJson() const override;

 private:
  json_t *json_;
  std::vector<MessageValidator*> children_;
  MessageValidator *root_;
};

#endif  // SRC_VALIDATORS_MESSAGEVALIDATORFACTORY_H_

