#include "claimset.h"
#include <string>
#include <memory>

const char* const ClaimSet::s_number[] = { "exp", "nbf", "iat" };
UtcClock ClaimSet::s_clock = UtcClock();

ClaimSet::ClaimSet(IClock* clock) : m_clock(clock), m_claimset(NULL) {
  m_clock = clock;
  m_claimset = json_object();
}

ClaimSet::ClaimSet() : m_clock(&s_clock), m_claimset(NULL) {
  m_claimset = json_object();
}

ClaimSet::~ClaimSet() {
  json_decref(m_claimset);
}

void ClaimSet::add(std::string key, std::string value) {
  json_object_set(m_claimset, key.c_str(), json_string(value.c_str()));
}

void ClaimSet::add(std::string key, int64_t value) {
  json_object_set(m_claimset, key.c_str(), json_integer(value));
}

bool ClaimSet::hasKey(std::string key) {
  json_t* object = json_object_get(m_claimset, key.c_str());
  return (object != NULL);
}

std::string ClaimSet::get(std::string key) {
  json_t* value = json_object_get(m_claimset, key.c_str());
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

bool ClaimSet::valid() {
  return validate_exp() && validate_iat() && validate_nbf();
}


bool ClaimSet::validate_exp() {
  json_t* object = json_object_get(m_claimset, "exp");
  if (object == NULL) {
    return true;
  }

  if  (!json_is_number(object)) {
    return false;
  }

  uint64_t date_ts = (uint64_t) json_integer_value(object);
  return date_ts < m_clock->currentTime();
}


bool ClaimSet::validate_iat() {
  json_t* object = json_object_get(m_claimset, "iat");
  if (object == NULL) {
    return true;
  }

  if  (!json_is_number(object)) {
    return false;
  }

  uint64_t date_ts = (uint64_t) json_integer_value(object);
  // Let's reject tokens issued in the future..
  return date_ts >= m_clock->currentTime();
}



bool ClaimSet::validate_nbf() {
  json_t* object = json_object_get(m_claimset, "nbf");
  if (object == NULL) {
    return true;
  }

  if  (!json_is_number(object)) {
    return false;
  }

  uint64_t date_ts = (uint64_t) json_integer_value(object);
  return date_ts < m_clock->currentTime();
}

std::string ClaimSet::toJson() {
  std::unique_ptr<char> pResult(json_dumps(m_claimset, JSON_INDENT(2)));
  return std::string(pResult.get());
}

ClaimSet* ClaimSet::parseJson(std::string json) {
  json_t *root;
  json_error_t error;

  root = json_loads(json.c_str(), JSON_REJECT_DUPLICATES, &error);

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
    for (int i = 0; i < array_size(ClaimSet::s_number); i++) {
      // Validate that it is a number
      if (strcmp(ClaimSet::s_number[i], key) == 0 && !json_is_number(value)) {
        json_decref(root);
        return nullptr;
      }
    }
  }

  // Overwrite existing claimset
  json_decref(claims->m_claimset);
  claims->m_claimset = root;
  return claims.release();
}
