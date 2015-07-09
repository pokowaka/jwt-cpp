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
#ifndef SRC_UTIL_ALLOCATORS_H_
#define SRC_UTIL_ALLOCATORS_H_
#include <jansson.h>
#include <memory>

class json_ptr_delete {
 public:
  // constexpr default_delete() noexcept {}
  // inline template <class U> default_delete(const default_delete<U>& d) noexcept { }
  inline void operator() (json_t* ptr) const noexcept {
    json_decref(ptr);
  }
};

class json_str_delete {
 public:
  inline void operator() (char* ptr) const noexcept {
    free(ptr);
  }
};

typedef std::unique_ptr<json_t, json_ptr_delete> unique_json_ptr;
typedef std::unique_ptr<char, json_str_delete> unique_json_str;
typedef std::unique_ptr<char[]> str_ptr;

#endif  // SRC_UTIL_ALLOCATORS_H_

