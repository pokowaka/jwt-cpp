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
#include "jwt/messagevalidator.h"
#include <string>

bool MessageValidator::Accepts(const json &jose) const {
    return jose.count("alg") &&
           jose["alg"].get<std::string>() == this->algorithm();
}

bool MessageValidator::Validate(const json &jsonHeader,
                                const std::string &header,
                                const std::string &signature) const {
    return Verify(
        jsonHeader,
        reinterpret_cast<uint8_t *>(const_cast<char *>(header.c_str())),
        header.size(),
        reinterpret_cast<uint8_t *>(const_cast<char *>(signature.c_str())),
        signature.size());
}

std::string MessageSigner::Digest(const std::string &header) const {
    size_t num_signature = 0;
    Sign(reinterpret_cast<const uint8_t *>(header.c_str()), header.size(), NULL,
         &num_signature);
    std::unique_ptr<uint8_t[]> signature(new uint8_t[num_signature]);
    if (!this->Sign(reinterpret_cast<const uint8_t *>(header.c_str()),
                    header.size(), signature.get(), &num_signature)) {
        throw std::logic_error("unable to sign header");
    }

    return std::string(reinterpret_cast<char *>(signature.get()),
                       num_signature);
}
