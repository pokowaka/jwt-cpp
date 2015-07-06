#include <string>
#include "claimset.h"

class Jwt {

 public:
    bool decode(std::string token);

 private:
    std::string encode_header();
    std::string encode_claimset();
    std::string encode_signature();

    ClaimSet* m_claimset;
    ClaimSet* m_header; // See sec 5.3 spec
};
