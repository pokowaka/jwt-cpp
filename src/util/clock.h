#include <sys/time.h>

/**
 * Clock interface, mainly used so we can stub out behavior.
 */
class IClock {
 public:
    virtual uint64_t Now()  = 0;
    virtual ~IClock() {}
};

class UtcClock : public IClock {
 public:
    uint64_t Now() {
      time_t rawtime;
      struct tm *ptm;
      time(&rawtime);
      ptm = gmtime(&rawtime);
      return mktime(ptm);
    }
};

class FakeClock : public IClock {
 public:
    explicit FakeClock(uint64_t time) { now_ = time; }
    inline uint64_t Now() { return now_; }
 private:
    uint64_t now_;
};
