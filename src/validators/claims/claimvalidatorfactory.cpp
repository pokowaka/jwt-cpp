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
#include "jwt/claimvalidatorfactory.h"
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include "jwt/allocators.h"
#include "jwt/listclaimvalidator.h"
#include "jwt/timevalidator.h"
#include "private/buildwrappers.h"

#include "jwt/json.hpp"
using json = nlohmann::json;

ClaimValidatorFactory::~ClaimValidatorFactory() {
    for (auto it = build_.begin(); it != build_.end(); it++) {
        delete *it;
    }
}

ClaimValidator *ClaimValidatorFactory::Build(const std::string &fromJson) {
    json json = json::parse(fromJson);
    return Build(json);
}

ClaimValidator *ClaimValidatorFactory::BuildInternal(const json &json) {
    if (json.empty()) {
        throw std::logic_error("Cannot construct from empty json!");
    }
    if (json.size() > 1) {
        std::ostringstream msg;
        msg << "More than one property at: " << json;
        throw std::logic_error(msg.str());
    }

    ClaimValidator *constructed = nullptr;
    try {
        if (json.count("iss")) {
            constructed = new IssValidator(BuildList(json["iss"]));
        } else if (json.count("sub")) {
            constructed = new SubValidator(BuildList(json["sub"]));
        } else if (json.count("aud")) {
            constructed = new AudValidator(BuildList(json["aud"]));
        } else if (json.count("exp")) {
            ::json val = json["exp"];
            ::json leeway = val["leeway"];
            constructed =
                new ExpValidator(leeway.is_null() ? 0 : leeway.get<int>());
        } else if (json.count("nbf")) {
            ::json val = json["nbf"];
            ::json leeway = val["leeway"];
            constructed =
                new NbfValidator(leeway.is_null() ? 0 : leeway.get<int>());
        } else if (json.count("iat")) {
            ::json val = json["iat"];
            ::json leeway = val["leeway"];
            constructed =
                new IatValidator(leeway.is_null() ? 0 : leeway.get<int>());
        } else if (json.count("all")) {
            constructed =
                new AllClaimValidator(BuildValidatorList(json["all"]));
        } else if (json.count("any")) {
            constructed =
                new AnyClaimValidator(BuildValidatorList(json["any"]));
        } else if (json.count("optional")) {
            ClaimValidator *inner = BuildInternal(json["optional"]);
            constructed = new OptionalClaimValidator(inner);
        }
    } catch (std::exception &le) {
        throw std::logic_error(
            std::string("Failed to construct validator at: ") + json.dump() +
            ", " + le.what());
    }

    if (!constructed) {
        throw std::logic_error(std::string("No validator declared at: ") +
                               json.dump());
    }

    build_.push_back(constructed);
    return constructed;
}

ClaimValidator *ClaimValidatorFactory::Build(const json &json) {
    ClaimValidatorFactory factory;

    ClaimValidator *root = factory.BuildInternal(json);
    ParsedClaimvalidator *validator =
        new ParsedClaimvalidator(json, factory.build_, root);
    factory.build_.clear();

    return validator;
}

std::vector<ClaimValidator *> ClaimValidatorFactory::BuildValidatorList(
    const json &json) {
    if (!json.is_array()) {
        throw std::logic_error(json.dump() + " is not an array!");
    }

    std::vector<ClaimValidator *> result;
    for (auto it = json.begin(); it != json.end(); ++it) {
        result.push_back(BuildInternal(*it));
    }

    return result;
}

std::vector<std::string> ClaimValidatorFactory::BuildList(const json &object) {
    if (!object.is_array()) {
        throw std::logic_error(object.dump() + " is not an array!");
    }

    std::vector<std::string> result;
    for (auto it = object.begin(); it != object.end(); ++it) {
        if (!it->is_string()) {
            throw std::logic_error("array can only contain strings");
        }
        result.push_back(it->get<std::string>());
    }

    return result;
}

ParsedClaimvalidator::ParsedClaimvalidator(
    const json &json, const std::vector<ClaimValidator *> &children,
    ClaimValidator *root)
    : ClaimValidator(root->property()),
      json_(json),
      children_(children),
      root_(root) {}

bool ParsedClaimvalidator::IsValid(const json &claimset) const {
    return root_->IsValid(claimset);
}

ParsedClaimvalidator::~ParsedClaimvalidator() {
    for (auto it = children_.begin(); it != children_.end(); it++) {
        delete *it;
    }
}

std::string ParsedClaimvalidator::toJson() const { return root_->toJson(); }
