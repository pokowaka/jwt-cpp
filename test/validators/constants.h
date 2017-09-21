#ifndef TEST_VALIDATORS_CONSTANTS_H_
#define TEST_VALIDATORS_CONSTANTS_H_

#include "private/clock.h"

class FakeClock : public IClock {
public:
  explicit FakeClock(uint64_t time) { now_ = time; }
  inline uint64_t Now() { return now_; }

private:
  uint64_t now_;
};

const char *privkey =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEA4SWe3cgEULKiz2wP+fYqN2TxEx6DiL4rvyqZfl0CFpVMH7wC\n"
    "ZqvglxOMtUzpdO7USdlFmyOEjtH1tioll9EAg6DMs0QrLgBj7U0XHRHeJcRrbYxm\n"
    "HqtmtRxjEmLBpClJoYaJ2fEdeaVcV5D1+kWMIRLM1q3RNafb1Q62nwSyojgX09/X\n"
    "+lWtkuX4NPwnn5NW13uhLyO96bANWMzPhYewwCsY7s7HCscNEhVTLQF0UmtYMgpn\n"
    "kzrR9aibtmCZhf58ebn0VjtoYu3JzhzmvUK+E3OZb0xp3e2f464owRIvWTlTte9h\n"
    "kDnkNKYoqY7fF/adwb8xDNZEAeYAwE0jC2tE3QIDAQABAoIBAQCsLgATba5XJHW8\n"
    "GNETAL2CRXDThUdkIMMF3AcsiuZY7O4dasOPTyxffPTjhaEX6rlwjHdd0EjEjC7T\n"
    "k+HR+2TgRO2mvqAi+utwg78EXTC9QzxAt9k05TGTmdTuL5YU+/oyS9hKUsmOyPYY\n"
    "hWSHc/5ZIK6EEsNmvCszAaCJdadCxCF9r/jTkT2iWVtV1Zrh7+Z/azX+wWSBIcEW\n"
    "Lbk6MGCt2z7mWGla4x7ToxhYWBhRdDxZ0R3VzG05e1Yjn1q2U5uxsSdBAPAISgeD\n"
    "7LpnwMs9NcjGnVO2cUHfK1fL7tLpMlqTsyflEyvFuN2+WatY7eaFeI/jRBb3ezYF\n"
    "IcNZD8eBAoGBAPnhgL1ZhpDZRJ+M/CjV0KQmbzoMyt5B38cDJ0VNZG/CObCMKwvI\n"
    "kMisBwFZEyS1oiV2Lt//8tLDnrlvxQrKQLmEzI5kCbuh3EUiG/tMF4VmKB4+JR/2\n"
    "TNsHCqeNuKmVjy+SYNkHDfO5MbdNBSSXaV4GuA1L3evzwTNOij39C8ThAoGBAOap\n"
    "D7XOigmuGMeOiFcivtGmCuOKfS8ZqTV2tKBcu3kv8F9CeqAFp/Qznxn/M8oi91VN\n"
    "rdDwkH9aClXXSjaj2FpWHCU+hQJUbzucClOf0VgExYsdwNwEDaVrwRbo+fCzt3Fy\n"
    "IdChwV7AO9sSggcGWbavbCU7F/h1g/BLHx/njYN9AoGAdQIDJqclO+6BE7UQ3o5A\n"
    "hJz6uFQFKs3t22K+oNT8kth/6wu3nGzuXwkuvpLXQ/lJVAFjMcDIE6lGSc7slYDf\n"
    "jf+BSavOYu4IFtdCAwo+eVi8sGypNa4/jtBdTNgwADjoM353myiSf+3YOdz264t6\n"
    "62x6Ar/jyvj5Hu1IDn7PZAECgYAdoYw+G8lJ0w6l3B6Rqwn+Xqk5b9oDCfXdw2ES\n"
    "1LbUq57ibeTY18EqstL2gP1DM1i4oaD5nV3CrmtzeZO0DzpE6Jj3A+AMW5JqgvIk\n"
    "qfw3pW1HIMxctzyVipEkg0tQa5XeQf4sEguIQ4Os8eS4SE2QFVr8MWoz5czMOqpF\n"
    "6/YW9QKBgERgOD3W9BcecygPNZfGZSZRVF0j5LT0PDgKr/02CIPu2mo+2ej9GmBP\n"
    "PnLXbe/R9SG8p2+Yh2ZfXn7FlXfr9a7MkzQWR/rpmxlDyzAyaJaI/vCBP+KknzPo\n"
    "zBJNQZl5S6qKrqr0ypYs6ekAQ5MEe3twWWyXG2y1QgeMIs3BTnJ1\n"
    "-----END RSA PRIVATE KEY-----";

const char *pubkey =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4SWe3cgEULKiz2wP+fYq\n"
    "N2TxEx6DiL4rvyqZfl0CFpVMH7wCZqvglxOMtUzpdO7USdlFmyOEjtH1tioll9EA\n"
    "g6DMs0QrLgBj7U0XHRHeJcRrbYxmHqtmtRxjEmLBpClJoYaJ2fEdeaVcV5D1+kWM\n"
    "IRLM1q3RNafb1Q62nwSyojgX09/X+lWtkuX4NPwnn5NW13uhLyO96bANWMzPhYew\n"
    "wCsY7s7HCscNEhVTLQF0UmtYMgpnkzrR9aibtmCZhf58ebn0VjtoYu3JzhzmvUK+\n"
    "E3OZb0xp3e2f464owRIvWTlTte9hkDnkNKYoqY7fF/adwb8xDNZEAeYAwE0jC2tE\n"
    "3QIDAQAB\n"
    "-----END PUBLIC KEY-----";

const char *hmacs[] = {"HS256", "HS384", "HS512"};
const char *rs[] = {"RS256", "RS384", "RS512"};

FakeClock fakeClock(11);
#endif // TEST_VALIDATORS_CONSTANTS_H_
