Jwt-cpp
=======

A C++11 implementation of the [JSON Web
Token](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html)
standard.

jwt-cpp is licensed under the [MIT license](http://opensource.org/licenses/mit-license.php); 
see LICENSE in the source distribution for details.

Currently it supports the following:

Sign, Verify JWS:

- HS256, HS384, HS512
- RS256, RS384, RS512
- *none*

Payload validators:

- iss check
- sub check
- aud check
- exp check
- nbf check
- iat check

**NOTE**: We keep private and public keys unencrypted in memory for the duration of the 
existence of any of the validators.

## Compilation and Installation

Jwt-cpp uses the [CMake](http://www.cmake.org/) cross platform build tools to
build. Once you have installed the proper dependencies you can do the following:

For release:

```
mkdir release 
cd release 
cmake -DCMAKE_BUILD_TYPE=Release ..
make install
```

For debug:
```
mkdir debug 
cd debug 
cmake -DCMAKE_BUILD_TYPE=Debug ..
make
```

Running the tests with code coverage:
```
mkdir debug 
cd debug 
cmake -DCMAKE_BUILD_TYPE=Debug ..
make cov_all_tests
```


### Dependencies in linux

You will need to install the following dependencies:
```
sudo apt-get install libssl-dev cmake lcov
```


### How to build in Mac OS

First make sure you have the proper dependencies. The easiest way is to use
[Homebrew](http://brew.sh/).

```
brew install cmake lcov openssl@1.1
```

### How to build in Windows
Beside cmake and Visual Studio, you need to install OpenSSL binaries:
[Win32 OpenSSL](https://slproweb.com/products/Win32OpenSSL.html)

After installation, configure cmake for your Visual Studio and set openssl folders:
```
MD build
CD build
cmake -G "Visual Studio 14" -DCMAKE_INSTALL_PREFIX=..\install -DOPENSSL_INCLUDE_DIRS=C:\OpenSSL-Win32\include -DOPENSSL_LIBRARY_DIRS=C:\OpenSSL-Win32\lib ..
cmake --build . --clean-first --target install
```
Find your binaries at `install` folder.

To run tests on Windows, add openssl bins to your path:
```
set "PATH=C:\OpenSSL-Win32\bin;%PATH%"
ctest
```

## Usage

You can find detailed [samples](test/token/sample.cpp) that are executed as part
of the tests.  We make use of [JSON for Modern C++](https://github.com/nlohmann/json) library 
to create json payload. 

### Signing tokens

For example we can create a signed token with HS256 as follows:

```cpp
#include <iostream>
#include "jwt/jwt_all.h"
using json = nlohmann::json;

int main() {
    // Setup a signer
    HS256Validator signer("secret!");

    // Create the json payload that expires 01/01/2017 @ 12:00am (UTC)
    json payload = {{"sub", "subject"}, {"exp", 1483228800}};

    // Let's encode the token to a string
    auto token = JWT::Encode(signer, payload);

    std::cout << token << std::endl;
}
```

On my mac with homebrew installed at ~/homebrew (it is usually in /usr/local) it can be compiled as follows:

```bash
g++ -std=c++11 \
-I ~/homebrew/include \
-I ~/homebrew/opt/openssl@1.1/include \
-L ~/homebrew/opt/openssl@1.1/lib \
-L ~/homebrew/lib -lcrypto -ljwt \
sign.cpp -o sign.cpp
```

Executing this should result in something like:

eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzdWJqZWN0IiwiZXhwIjoxNDgzMjI4ODAwfQ.4Vjr_Htx4oBy9cHFNbpLsVC_YgIA4_hrUIV1unApUUs

### Validating tokens
Validation is straightforward:

```cpp
#include <iostream>
#include "jwt/jwt_all.h"
using json = nlohmann::json;

int main() {
    ExpValidator exp;
    HS256Validator signer("secret!");

    // Now let's use these validators to parse and verify the token we created
    // in the previous example
    std::string str_token =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
        "eyJpc3MiOiJmb28iLCJleHAiOjE0ODMyMjg4MDB9."
        "u3JTUx1tJDo601olQv0rHk4kGkKadIj3cvy-DDZKVRo";
    try {
        // Decode and validate the token
        ::json header, payload;

        std::tie(header, payload) = JWT::Decode(str_token, &signer, &exp);
        std::cout << "Header: " << header << std::endl;
        std::cout << "Payload: " << payload << std::endl;
    } catch (InvalidTokenError &tfe) {
        // An invalid token
        std::cout << "Validation failed: " << tfe.what() << std::endl;
    }
}
```

Again we compile it:

```bash
g++ -std=c++11  \
-I ~/homebrew/include \
-I ~/homebrew/opt/openssl@1.1/include \
-L ~/homebrew/opt/openssl@1.1/lib \
-L ~/homebrew/lib -lcrypto -ljwt -lssl \
validate.cpp -o validate
```

#### An example using factories
Usually your validators will be a little more complex than just validating one
property. The easiest way to use more complex verifiers and validators is by
using ``ClaimValidatorFactory::Build`` or ``MessageValidatorFactory::Build``.
Both methods accept a json string or a json object, and produce a claim validator or message
validator. 

```cpp
#include <iostream>
#include "jwt/jwt_all.h"
using json = nlohmann::json;

int main() {
    // Let's setup a claim validator where we will accept tokens that
    // are have been issues by either foo or bar
    // and have an optional expiration claim with a leeway of 32s.
    std::string json_claim =
        "{ \"all\" : "
        "  [ "
        "    { \"optional\" : { \"exp\" : { \"leeway\" : 32} } },"
        "    { \"iss\" : [\"foo\", \"bar\"] }"
        "  ]"
        "}";

    // Lets build the claim validator
    claim_ptr claim_validator(ClaimValidatorFactory::Build(json_claim));

    // Next we are going to setup the message validators. We will accept
    // the HS256 & HS512 validators with the given secrets.
    std::string json_validators =
        "{ \"set\" : [ "
        "  { \"HS256\" : { \"secret\" : \"secret!\" } }, "
        "  { \"HS512\" : { \"secret\" : \"supersafe\" } }"
        " ]"
        "}";
    validator_ptr message_validator(
        MessageValidatorFactory::Build(json_validators));

    // Now let's use these validators to parse and verify the token we created
    // with a previous sample.
    std::string str_token =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
        "eyJpc3MiOiJmb28iLCJleHAiOjE0ODMyMjg4MDB9."
        "u3JTUx1tJDo601olQv0rHk4kGkKadIj3cvy-DDZKVRo";
    try {
        ::json header, payload;
        std::tie(header, payload) = JWT::Decode(
            str_token, message_validator.get(), claim_validator.get());
        std::cout << "Header: " << header << std::endl;
        std::cout << "Payload: " << payload << std::endl;
    } catch (InvalidTokenError &tfe) {
        std::cout << tfe.what() << std::endl;
    }
}
```

Again compile and run it:

```bash
g++ -std=c++11  \
-I ~/homebrew/include \
-I ~/homebrew/opt/openssl@1.1/include \
-L ~/homebrew/opt/openssl@1.1/lib \
-L ~/homebrew/lib -lcrypto -ljwt -lssl \
factories.cpp -o factories
```
#### Dealing with failures
There will come a time when tokens are not valid. When tokens fail to validate exceptions will be thrown:

- **InvalidTokenError**: base class for token errors
- **TokenFormatError**: the token is wrongly encoded. No information can be retrieved.
- **InvalidSignatureError**: failed to verify the signature. You can still retrieve the token by disabling verification.
- **InvalidClaimError**: failed to verify the claims. You can still retrieve the token by disabling validation
- **std::logic_error**: you should never see this. If you do a bug needs to be fixed.

The sample below shows how you can deal with errors:

```cpp
#include <iostream>
#include "jwt/jwt_all.h"
using json = nlohmann::json;

int main() {
    ExpValidator exp;
    HS256Validator signer("secret");

    // Now we use these validators to parse and verify the token we created
    // in the previous example
    std::string token =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
        "eyJpc3MiOiJmb28iLCJleHAiOjE0ODMyMjg4MDB9."
        "u3JTUx1tJDo601olQv0rHk4kGkKadIj3cvy-DDZKVRo";
    try {
        json header, payload;
        std::tie(header, payload) = JWT::Decode(token, &signer, &exp);
        std::cout << "You should not see this line" << std::endl;
    } catch (TokenFormatError &tfe) {
        // No data can be recovered..
    } catch (InvalidTokenError &tfe) {
        json header, payload;
        std::tie(header, payload) = JWT::Decode(token);
        std::cout << "Payload: " << payload << std::endl;
    }
}
```

Again compile and run it:

```bash
g++ -std=c++11  \
-I ~/homebrew/include \
-I ~/homebrew/opt/openssl@1.1/include \
-L ~/homebrew/opt/openssl@1.1/lib \
-L ~/homebrew/lib -lcrypto -ljwt -lssl \
failed.cpp -o failed
```

Should result in something like this:

```
Payload: {"exp":1483228800,"iss":"foo"}
```

## The JSON Factories
The json factories make it easier to construct signers and validators. The BNF schemas below show you how you can construct signers. Note that signers can also be used as validators as well.

```
signer ::= 
  "none"  : null |
  "HS256" : { "secret" : "*your actual secret*} |
  "HS384" : { "secret" : "*your actual secret*} |
  "HS512" : { "secret" : "*your actual secret*" } |
  "RS256" : { "public"  : ("PEM block with key" | { "fromfile" : "/path/to/file/with/pem" }), 
              "private" : ("PEM..." | { "fromfile" : "...." }) } |
  "RS384" : { "public"  : ("PEM..." | { "fromfile" : "...." }), 
              "private" : ("PEM..." | { "fromfile" : "...." }) } |
  "RS512" : { "public"  : ("PEM..." | { "fromfile" : "...." }), 
              "private" : ("PEM..." | { "fromfile" : "...." }) } |
```

The BNF used to construct validators looks as follows:

```
validator ::= 
  "none"  : null |
  "HS256" : { "secret" : "...." } |
  "HS384" : { "secret" : "...." } |
  "HS512" : { "secret" : "...." } |
  "RS256" : { "public" : ("PEM..." | { "fromfile" : "...." }) } |  
  "RS384" : { "public" : ("PEM..." | { "fromfile" : "...." }) } |
  "RS512" : { "public" : ("PEM..." | { "fromfile" : "...." }) } |
  "set"   : [ validator+ ] |
  "kid"   : ( { id : validator } )+   
```

- A **set** validator will accept the token if any of the validators in the set accepts the token.
- A **kid** validator will accept the token if the kid field of the token is
  validated by the given validator. See the [sample](test/token/sample.cpp) for more details on how this works. 

You can build a MessageValidator by invoking the factory:
``MessageValidator* MessageValidatorFactory::Build(std::string toBuild)``
``MessageSigner* MessageValidatorFactory::BuildSigner(std::string toBuild)``

*Note: Never include the none validator alongside other validators! See this
[blog post](https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/)
for details.*	

Claimvalidators:

```
claims ::=
  single_claim |
  "optional" : { (single_claim) } |
  "any" : [ (claim)+ ] |
  "all" : [ (claim)+ ] 
 single_claim ::= 
  "exp" : (null | { "leeway" : .... }) |
  "nbf" : (null | { "leeway" : .... }) |
  "iat" : (null | { "leeway" : .... }) |
  "iss" : [ "..."+ ] |
  "sub" : [ "..."+ ] |
  "aud" : [ "..."+ ] |
```

For example:

```
{
   "all":[
      {
         "optional":{ "exp":{ "leeway":32 } }
      },
      {
         "iss":[ "foo", "bar" ]
      }
   ]
}
```

Indicates that the claims set has the following:

- If an expiration is set, its expiration should be no later than the current time + 32 seconds
- It has been issued by either *foo*, or *bar*
