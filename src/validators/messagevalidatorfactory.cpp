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
#include "validators/messagevalidatorfactory.h"
#include <jansson.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include "util/allocators.h"
#include "validators/hmacvalidator.h"
#include "validators/kidvalidator.h"
#include "validators/nonevalidator.h"
#include "validators/rsavalidator.h"
#include "validators/setvalidator.h"


MessageValidatorFactory::~MessageValidatorFactory() {
  for (auto it = build_.begin(); it != build_.end(); it++) {
    delete *it;
  }
}

MessageValidator *MessageValidatorFactory::build(json_t *json) {
  if (json == NULL) {
    throw std::logic_error("Cannot construct from empty json!");
  }
  if (json_object_size(json) > 1) {
    char *fail = json_dumps(json, 0);
    std::ostringstream msg;
    msg << "More than one property at: " << fail;
    free(fail);
    throw std::logic_error(msg.str());
  }

  std::unique_ptr<MessageValidator> constructed = nullptr;
  if (json_object_get(json, "none")) {
    constructed.reset(new NoneValidator());
  } else if (json_object_get(json, "HS256")) {
    constructed.reset(new HS256Validator(ParseSecret("secret", json_object_get(json, "HS256"))));
  } else if (json_object_get(json, "HS384")) {
    constructed.reset(new HS384Validator(ParseSecret("secret", json_object_get(json, "HS384"))));
  } else if (json_object_get(json, "HS512")) {
    constructed.reset(new HS512Validator(ParseSecret("secret", json_object_get(json, "HS512"))));
  } else if (json_object_get(json, "RS256")) {
    constructed.reset(new RS256Validator(ParseSecret("public", json_object_get(json, "RS256"))));
  } else if (json_object_get(json, "RS384")) {
    constructed.reset(new RS384Validator(ParseSecret("public", json_object_get(json, "RS384"))));
  } else if (json_object_get(json, "RS512")) {
    constructed.reset(new RS512Validator(ParseSecret("public", json_object_get(json, "RS512"))));
  }

  try {
    if (json_object_get(json, "set")) {
      auto lst = buildvalidatorlist(json_object_get(json, "set"));
      constructed.reset(new SetValidator(lst));
    } else if (json_object_get(json, "kid")) {
      KidValidator *kid = new KidValidator();
      constructed.reset(kid);
      buildkid(kid, json_object_get(json, "kid"));
    }
  } catch (std::exception &le) {
    std::ostringstream msg;
    msg << "Json error inside: " << le.what();
    char *fail = json_dumps(json, 0);
    if (fail) {
      msg << ", at: " << fail;
      free(fail);
    }

    throw std::logic_error(msg.str());
  }

  if (!constructed.get()) {
    char *fail = json_dumps(json, 0);
    if (fail) {
      std::ostringstream msg;
      msg << "Missing property at: " << fail;
      free(fail);
      throw std::logic_error(msg.str());
    }
    throw std::logic_error("Missing property");
  }

  build_.push_back(constructed.get());
  return constructed.release();
}


MessageValidator *MessageValidatorFactory::build(std::string fromJson) {
  json_error_t error;
  json_ptr json_str(json_loads(fromJson.c_str(), JSON_REJECT_DUPLICATES, &error));

  if (!json_str) {
    std::ostringstream msg;
    msg << "Failed to parse JSON: " << error.text
      << ", at line: " << error.line << ", col: " << error.column;
    throw std::logic_error(msg.str());
  }

  MessageValidatorFactory factory;

  MessageValidator *root = factory.build(json_str.get());
  ParsedMessagevalidator *validator = new ParsedMessagevalidator(
      json_str.release(), factory.build_, root);
  factory.build_.clear();

  return validator;
}

std::vector<MessageValidator *> MessageValidatorFactory::buildvalidatorlist(json_t *json) {
  size_t idx;
  json_t *value;
  std::vector<MessageValidator *> result;

  json_array_foreach(json, idx, value) {
    result.push_back(build(value));
  }

  return result;
}

MessageValidator *MessageValidatorFactory::buildkid(KidValidator *kid, json_t *kidlist) {
  const char *key;
  json_t *value;

  json_object_foreach(kidlist , key, value) {
    MessageValidator* validator = build(value);
    kid->Register(key, validator);
  }

  return kid;
}

std::string MessageValidatorFactory::ParseSecret(const char *property, json_t *object) {
  json_t *secret = json_object_get(object, property);
  if (!secret) {
    throw std::logic_error("There is no secret!");
  }

  if (json_is_string(secret)) {
    return json_string_value(secret);
  }

  json_t *fromfile = json_object_get(secret, "fromfile");
  if (!json_is_string(fromfile))
    throw std::logic_error("fromfile is not specified");

  std::ifstream t(json_string_value(fromfile));
  std::stringstream buffer;
  buffer << t.rdbuf();
  return buffer.str();
}

bool ParsedMessagevalidator::Verify(json_t *jsonHeader, const uint8_t *header, size_t num_header,
    const uint8_t *signature, size_t num_signature) {
  return root_->Verify(jsonHeader, header, num_header, signature, num_signature);
}

const char *ParsedMessagevalidator::algorithm() const {
  return root_->algorithm();
}

std::string ParsedMessagevalidator::toJson() const {
  return root_->toJson();
}

ParsedMessagevalidator::~ParsedMessagevalidator() {
  for (auto it = children_.begin(); it != children_.end(); it++) {
    delete *it;
  }
  json_decref(json_);
}

bool ParsedMessagevalidator::Accepts(const char *algorithm) const {
  return root_->Accepts(algorithm);
}

ParsedMessagevalidator::ParsedMessagevalidator(json_t *json,
    const std::vector<MessageValidator *> &children, MessageValidator *root)
: json_(json), children_(children), root_(root) {
}
