#include <sys/time.h>

class IClock {
 public:
    virtual uint64_t currentTime()  = 0;
    virtual ~IClock() {}
};

class UtcClock : public IClock {
 public:
    uint64_t currentTime() {
      time_t rawtime;
      struct tm *ptm;
      time(&rawtime);
      ptm = gmtime(&rawtime);
      return mktime(ptm);
    }
};

class FakeClock : public IClock {
 public:
    explicit FakeClock(uint64_t time) { m_time = time; }
    uint64_t currentTime() { return m_time; }
 private:
    uint64_t m_time;
};
