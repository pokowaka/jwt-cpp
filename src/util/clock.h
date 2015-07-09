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
#ifndef SRC_UTIL_CLOCK_H_
#define SRC_UTIL_CLOCK_H_

#include <time.h>

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
      struct tm ptm;
      time(&rawtime);
      gmtime_r(&rawtime, &ptm);
      return mktime(&ptm);
    }
};

class FakeClock : public IClock {
 public:
    explicit FakeClock(uint64_t time) { now_ = time; }
    inline uint64_t Now() { return now_; }
 private:
    uint64_t now_;
};

#endif  // SRC_UTIL_CLOCK_H_
