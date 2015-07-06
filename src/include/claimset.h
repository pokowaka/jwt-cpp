#include <jansson.h>
#include <string>
#include <map>
#include "clock.h"

template<size_t SIZE, class T> inline size_t array_size(T (&arr)[SIZE]) {
  return SIZE;
}

/** A set of claims, internally backed by a jansson object */
class ClaimSet {
 public:
    ClaimSet();
    explicit ClaimSet(IClock* clock);
    ~ClaimSet();

    void add(std::string key, std::string value);
    void add(std::string key, int64_t value);
    bool hasKey(std::string key);
    std::string get(std::string key);
    bool valid();

    inline void setClock(IClock* clock) { m_clock = clock; }
    std::string toJson();
    static ClaimSet* parseJson(std::string);

 private:
    IClock* m_clock;
    json_t* m_claimset;

    bool validate_exp();
    bool validate_iat();
    bool validate_nbf();
    static const char* const s_number[];
    static UtcClock s_clock;
};


