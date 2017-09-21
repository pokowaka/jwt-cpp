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
#ifndef SRC_INCLUDE_JWT_MESSAGEVALIDATORFACTORY_H_
#define SRC_INCLUDE_JWT_MESSAGEVALIDATORFACTORY_H_

#include "json.hpp"
#include "jwt/kidvalidator.h"
#include "jwt/messagevalidator.h"
#include <exception>
#include <jansson.h>
#include <string>
#include <vector>

using json = nlohmann::json;

class MessageValidatorFactory {
public:
  static MessageValidator *Build(std::string msg);
  static MessageValidator *Build(json msg);
  static MessageSigner *BuildSigner(std::string msg);
  static MessageSigner *BuildSigner(json sign);

  ~MessageValidatorFactory();

private:
  static std::string ParseSecret(std::string property, json object);

  std::vector<std::string> BuildList(json lst);
  std::vector<MessageValidator *> BuildValidatorList(json list);
  MessageValidator *BuildInternal(json fromJson);
  MessageValidator *BuildKid(KidValidator *kid, json kidlist);

  std::vector<MessageValidator *> build_;
};

#endif // SRC_INCLUDE_JWT_MESSAGEVALIDATORFACTORY_H_
