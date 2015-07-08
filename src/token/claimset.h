#ifndef TOKEN_CLAIMSET_H
#define TOKEN_CLAIMSET_H

#include <jansson.h>
#include <string>
#include <map>
#include "util/clock.h"


/** A set of claims, internally backed by a jansson object */
class ClaimSet {
public:
    ClaimSet();

    explicit ClaimSet(IClock *clock);

    ~ClaimSet();

    void Add(std::string key, std::string value);

    void Add(std::string key, int64_t value);

    bool HasKey(std::string key);

    std::string Get(std::string key);

    bool Valid();

    inline void set_clock(IClock *clock) { clock_ = clock; }

    std::string toJson();

    static ClaimSet *parseJson(const char *json);

private:
    bool ValidateExp();
    bool ValidateIat();
    bool ValidateNbf();

    IClock *clock_;
    json_t *claimset_;

    static const char *const number_fields_[];
    static UtcClock utc_clock_;
};

#endif //TOKEN_CLAIMSET_H
