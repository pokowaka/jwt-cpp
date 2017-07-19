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
#ifndef SRC_INCLUDE_PRIVATE_CLOCK_H_
#define SRC_INCLUDE_PRIVATE_CLOCK_H_

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
      time_t rawtime = 0;
      struct tm ptm = {0};
      time(&rawtime);
      #ifdef _WIN32
      gmtime_s(&ptm, &rawtime);
      #else
      gmtime_r(&rawtime, &ptm);
      #endif
      return timegm(&ptm);
    }
};
#endif  // SRC_INCLUDE_PRIVATE_CLOCK_H_
