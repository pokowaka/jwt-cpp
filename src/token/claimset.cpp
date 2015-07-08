#include "token/claimset.h"
#include <string>
#include <memory>

template<size_t SIZE, class T> inline size_t array_size(T (&arr)[SIZE]) {
  return SIZE;
}

const char* const ClaimSet::number_fields_[] = { "exp", "nbf", "iat" };
UtcClock ClaimSet::utc_clock_ = UtcClock();

ClaimSet::ClaimSet(IClock* clock) : clock_(clock), claimset_(NULL) {
  clock_ = clock;
  claimset_ = json_object();
}

ClaimSet::ClaimSet() : clock_(&utc_clock_), claimset_(NULL) {
  claimset_ = json_object();
}

ClaimSet::~ClaimSet() {
  json_decref(claimset_);
}

void ClaimSet::Add(std::string key, std::string value) {
  json_object_set(claimset_, key.c_str(), json_string(value.c_str()));
}

void ClaimSet::Add(std::string key, int64_t value) {
  json_object_set(claimset_, key.c_str(), json_integer(value));
}

bool ClaimSet::HasKey(std::string key) {
  json_t* object = json_object_get(claimset_, key.c_str());
  return (object != NULL);
}

std::string ClaimSet::Get(std::string key) {
  json_t* value = json_object_get(claimset_, key.c_str());
  if (value == NULL) {
    return "";
  }

  if (json_is_string(value)) {
    return std::string(json_string_value(value));
  } else {
    std::unique_ptr<char> str(json_dumps(value, JSON_ENCODE_ANY));
    return std::string(str.get());
  }
}

bool ClaimSet::Valid() {
  return ValidateExp() && ValidateIat() && ValidateNbf();
}


bool ClaimSet::ValidateExp() {
  json_t* object = json_object_get(claimset_, "exp");
  if (object == NULL) {
    return true;
  }

  if  (!json_is_number(object)) {
    return false;
  }

  uint64_t date_ts = (uint64_t) json_integer_value(object);
  return date_ts < clock_->Now();
}


bool ClaimSet::ValidateIat() {
  json_t* object = json_object_get(claimset_, "iat");
  if (object == NULL) {
    return true;
  }

  if  (!json_is_number(object)) {
    return false;
  }

  uint64_t date_ts = (uint64_t) json_integer_value(object);
  // Let's reject tokens issued in the future..
  return date_ts >= clock_->Now();
}



bool ClaimSet::ValidateNbf() {
  json_t* object = json_object_get(claimset_, "nbf");
  if (object == NULL) {
    return true;
  }

  if  (!json_is_number(object)) {
    return false;
  }

  uint64_t date_ts = (uint64_t) json_integer_value(object);
  return date_ts < clock_->Now();
}

std::string ClaimSet::toJson() {
  std::unique_ptr<char> pResult(json_dumps(claimset_, JSON_INDENT(2)));
  return std::string(pResult.get());
}

ClaimSet* ClaimSet::parseJson(const char* json) {
  json_t *root;
  json_error_t error;

  root = json_loads(json, JSON_REJECT_DUPLICATES, &error);

  if (!root) {
    return nullptr;
  }

  if (!json_is_object(root)) {
    json_decref(root);
    return nullptr;
  }

  const char *key;
  json_t *value;
  std::unique_ptr<ClaimSet> claims(new ClaimSet());

  json_object_foreach(root, key, value) {
    for (int i = 0; i < array_size(ClaimSet::number_fields_); i++) {
      // Validate that it is a number
      if (strcmp(ClaimSet::number_fields_[i], key) == 0 && !json_is_number(value)) {
        json_decref(root);
        return nullptr;
      }
    }
  }

  // Overwrite existing claimset
  json_decref(claims->claimset_);
  claims->claimset_ = root;
  return claims.release();
}
