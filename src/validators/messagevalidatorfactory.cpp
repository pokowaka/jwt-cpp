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
#include "jwt/messagevalidatorfactory.h"
#include "jwt/allocators.h"
#include "jwt/hmacvalidator.h"
#include "jwt/json.hpp"
#include "jwt/kidvalidator.h"
#include "jwt/nonevalidator.h"
#include "jwt/rsavalidator.h"
#include "jwt/setvalidator.h"
#include "private/buildwrappers.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

using json = nlohmann::json;

MessageValidatorFactory::~MessageValidatorFactory() {
  for (auto &it : build_) {
    delete it;
  }
}

MessageValidator *MessageValidatorFactory::Build(const std::string &msg) {
  return Build(json::parse(msg));
};
MessageSigner *MessageValidatorFactory::BuildSigner(const std::string &msg) {
  return BuildSigner(json::parse(msg));
};

MessageSigner *MessageValidatorFactory::BuildSigner(const json &json) {
  if (json.size() > 1) {
    std::ostringstream msg;
    msg << "More than one property at: " << json;
    throw std::logic_error(msg.str());
  }

  std::unique_ptr<MessageSigner> constructed = nullptr;
  if (json.count("none") != 0u) {
    constructed.reset(new NoneValidator());
  } else if (json.count("HS256") != 0u) {
    constructed.reset(new HS256Validator(ParseSecret("secret", json["HS256"])));
  } else if (json.count("HS384") != 0u) {
    constructed.reset(new HS384Validator(ParseSecret("secret", json["HS384"])));
  } else if (json.count("HS512") != 0u) {
    constructed.reset(new HS512Validator(ParseSecret("secret", json["HS512"])));
  } else if (json.count("RS256") != 0u) {
    constructed.reset(
        new RS256Validator(ParseSecret("public", json["RS256"]),
                           ParseSecret("private", json["RS256"])));
  } else if (json.count("RS384") != 0u) {
    constructed.reset(
        new RS384Validator(ParseSecret("public", json["RS384"]),
                           ParseSecret("private", json["RS384"])));
  } else if (json.count("RS512") != 0u) {
    constructed.reset(
        new RS512Validator(ParseSecret("public", json["RS512"]),
                           ParseSecret("private", json["RS512"])));
  }

  if (constructed == nullptr) {
    throw std::logic_error("Unable to construct signer");
  }

  return constructed.release();
}

MessageValidator *MessageValidatorFactory::BuildInternal(const json &json) {
  if (json.size() > 1) {
    std::ostringstream msg;
    msg << "More than one property at: " << json;
    throw std::logic_error(msg.str());
  }

  std::unique_ptr<MessageValidator> constructed = nullptr;
  try {
    if (json.count("none") != 0u) {
      constructed.reset(new NoneValidator());
    } else if (json.count("HS256") != 0u) {
      constructed.reset(
          new HS256Validator(ParseSecret("secret", json["HS256"])));
    } else if (json.count("HS384") != 0u) {
      constructed.reset(
          new HS384Validator(ParseSecret("secret", json["HS384"])));
    } else if (json.count("HS512") != 0u) {
      constructed.reset(
          new HS512Validator(ParseSecret("secret", json["HS512"])));
    } else if (json.count("RS256") != 0u) {
      constructed.reset(
          new RS256Validator(ParseSecret("public", json["RS256"])));
    } else if (json.count("RS384") != 0u) {
      constructed.reset(
          new RS384Validator(ParseSecret("public", json["RS384"])));
    } else if (json.count("RS512") != 0u) {
      constructed.reset(
          new RS512Validator(ParseSecret("public", json["RS512"])));
    } else if (json.count("set") != 0u) {
      auto lst = BuildValidatorList(json["set"]);
      constructed.reset(new SetValidator(lst));
    } else if (json.count("kid") != 0u) {
      auto *kid = new KidValidator();
      constructed.reset(kid);
      BuildKid(kid, json["kid"]);
    }
  } catch (std::exception &e) {
    throw std::logic_error(std::string("Failed to construct validator at: ") +
                           json.dump() + ", " + e.what());
  }

  if (constructed == nullptr) {
    throw std::logic_error(std::string("No validator declared at: ") +
                           json.dump());
  }

  build_.push_back(constructed.get());
  return constructed.release();
}

MessageValidator *MessageValidatorFactory::Build(const json &json) {
  MessageValidatorFactory factory;

  MessageValidator *root = factory.BuildInternal(json);
  auto *validator = new ParsedMessagevalidator(json, factory.build_, root);
  factory.build_.clear();

  return validator;
}

std::vector<MessageValidator *>
MessageValidatorFactory::BuildValidatorList(const json &j) {
  std::vector<MessageValidator *> result;

  for (const auto &it : j) {
    result.push_back(BuildInternal(it));
  }

  return result;
}

MessageValidator *MessageValidatorFactory::BuildKid(KidValidator *kid,
                                                    const json &j) {
  for (auto it = j.begin(); it != j.end(); ++it) {
    MessageValidator *validator = BuildInternal(it.value());
    kid->Register(it.key(), validator);
  }

  return kid;
}

std::string MessageValidatorFactory::ParseSecret(const std::string &property,
                                                 const json &object) {
  if (object.count(property) == 0) {
    std::ostringstream msg;
    msg << "parsing secret, property: " << property
        << " is missing from: " << object;
    throw std::logic_error(msg.str());
  }

  json secret = object[property];
  if (secret.is_string()) {
    return secret.get<std::string>();
  }

  if (secret.count("fromfile") != 0u) {
    std::ifstream t(secret["fromfile"].get<std::string>());
    std::stringstream buffer;
    buffer << t.rdbuf();
    return buffer.str();
  }

  throw std::logic_error("fromfile is not specified");
}

bool ParsedMessagevalidator::Verify(const json &jose, const uint8_t *header,
                                    size_t num_header, const uint8_t *signature,
                                    size_t num_signature) const {
  return root_->Verify(jose, header, num_header, signature, num_signature);
}

std::string ParsedMessagevalidator::algorithm() const {
  return root_->algorithm();
}

std::string ParsedMessagevalidator::toJson() const { return root_->toJson(); }

ParsedMessagevalidator::~ParsedMessagevalidator() {
  for (auto &it : children_) {
    delete it;
  }
}

bool ParsedMessagevalidator::Accepts(const json &jose) const {
  return root_->Accepts(jose);
}

ParsedMessagevalidator::ParsedMessagevalidator(
    json json, std::vector<MessageValidator *> children, MessageValidator *root)
    : json_(std::move(json)), children_(std::move(children)), root_(root) {}
