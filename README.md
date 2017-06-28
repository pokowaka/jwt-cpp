Jwt-cpp
=======

A C++ implementation of the [JSON Web
Token](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html)
standard. It is written in C++11, but the compiled library can be used in C++

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
brew install cmake lcov
brew upgrade openssl
brew link --force openssl
pkg-config --modversion openssl
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
of the tests.  We make use of [jansson](http://www.digip.org/jansson/) library 
to create json payload.

Throughout the samples we make use of auto pointers:

```cpp
typedef std::unique_ptr<JWT> jwt_ptr;
typedef std::unique_ptr<json_t, json_ptr_delete> json_ptr;
typedef std::unique_ptr<char, json_str_delete> json_str;
typedef std::unique_ptr<char[]> str_ptr;
```

### Signing tokens

For example we can create a signed token with HS256 as follows:

```cpp
#include "jwt/jwt_all.h"

int main() {
  // Setup a signer
  HS256Validator signer("secret!");

  // Create the json payload that expires 01/01/2017 @ 12:00am (UTC)
  json_ptr json(json_pack("{ss, si}", "sub", "subject", "exp", 1483228800));

  // Let's encode the token to a char[]
  str_ptr str_token(JWT::Encode(&signer, json.get()));

  printf("%s\n", str_token.get());
}
```

We can compile and run the sample in Mac OS as follows:

``g++ test.cpp -ljansson -ljwt -lcrypto -L /usr/local/lib -o test``

Executing this should result in something like:

eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzdWJqZWN0IiwiZXhwIjoxNDgzMjI4ODAwfQ.4Vjr_Htx4oBy9cHFNbpLsVC_YgIA4_hrUIV1unApUUs

### Validating tokens
Validation is straightforward:

```cpp
#include "jwt/jwt_all.h"

int main() {
  ExpValidator exp;
  HS256Validator signer("secret!");

  // Now let's use these validators to parse and verify the token we created in the previous example
  std::string str_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
    "eyJpc3MiOiJmb28iLCJleHAiOjE0ODMyMjg4MDB9."
    "u3JTUx1tJDo601olQv0rHk4kGkKadIj3cvy-DDZKVRo";
  try {
    jwt_ptr token(JWT::Decode(str_token, &signer, &exp));
    json_str payload(json_dumps(token->payload(), JSON_INDENT(2)));
    printf("Payload: %s\n", payload.get());
  } catch (InvalidTokenError &tfe) {
    // An invalid token
    printf("Validation failed: %s\n", tfe.what());
  }
}


```

#### An example using factories
Usually your validators will be a little more complex than just validating one
property. The easiest way to use more complex verifiers and validators is by
using ``ClaimValidatorFactory::Build`` or ``MessageValidatorFactory::Build``.
Both methods accept a json string, and produce a claim validator or message
validator. 

```cpp
#include "jwt/jwt_all.h"

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
  validator_ptr message_validator(MessageValidatorFactory::Build(json_validators));

  // Now let's use these validators to parse and verify the token we created
  // with a previous sample.
  std::string str_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
    "eyJpc3MiOiJmb28iLCJleHAiOjE0ODMyMjg4MDB9."
    "u3JTUx1tJDo601olQv0rHk4kGkKadIj3cvy-DDZKVRo";
  try {
    jwt_ptr token(JWT::Decode(str_token, message_validator.get(), claim_validator.get()));
    json_str payload(json_dumps(token->payload(), JSON_INDENT(2)));
    printf("Payload: %s\n", payload.get());
  } catch (InvalidTokenError &tfe) {
    // Badly token
    printf("Validation failed: %s\n", tfe.what());
  }
}
```

Again compile and run it:

``g++ test.cpp -ljansson -ljwt -lcrypto -L /usr/local/lib -o test``

#### Dealing with failures
There will come a time when tokens are not valid. When tokens fail to validate exceptions will be thrown:

- **InvalidTokenError**: base class for token errors
- **TokenFormatError**: the token is wrongly encoded. No information can be retrieved.
- **InvalidSignatureError**: failed to verify the signature. You can still retrieve the token by disabling verification.
- **InvalidClaimError**: failed to verify the claims. You can still retrieve the token by disabling validation
- **std::logic_error**: you should never see this. If you do a bug needs to be fixed.

The sample below shows how you can deal with errors:

```cpp
#include "jwt/jwt_all.h"

int main() {
  ExpValidator exp;
  HS256Validator signer("secret");

  // Now let's use these validators to parse and verify the token we created in the previous example
  std::string str_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJmb28iLCJleHAiOjE0ODMyMjg4MDB9.u3JTUx1tJDo601olQv0rHk4kGkKadIj3cvy-DDZKVRo";
  try {
    jwt_ptr token(JWT::Decode(str_token, &signer, &exp));
    json_str payload(json_dumps(token->payload(), JSON_INDENT(2)));
    printf("Payload: %s\n", payload.get());
  } catch (TokenFormatError &tfe) {
    // No data can be recovered..
  } catch (InvalidTokenError &tfe) {
    // Bad token signature, lets disable the validation..
    printf("Validation failed: %s\n", tfe.what());
    jwt_ptr token(JWT::Decode(str_token));
    json_str payload(json_dumps(token->payload(), JSON_INDENT(2)));
    printf("Payload: %s\n", payload.get());
  }
}

```

Again compile and run it:

``g++ test.cpp -ljansson -ljwt -lcrypto -L /usr/local/lib -o test``

Should result in something like this:

```
Validation failed: Unable to verify signature
Payload: {
  "iss": "foo",
  "exp": 1483228800
}
```

## The JSON Factories
Here's the schema used to produce the various signers/validators:

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

- A **set** validator will accept the token if any of the validators in the set
accepts the token.
- A **kid** validator will accept the token if the kid field of the token is
  validated by the given validator. See the [sample](test/token/sample.cpp) for
  more details. *Note*: Be careful when associating claim validators with this validator.
  if you rely for example that the *iss* property relates to a specific kid. (i.e. if the 
    issuer is foo, then the kid field should be 2, not 3).

You can build a MessageValidator by invoking the factory:
``MessageValidator* MessageValidatorFactory::Build(std::string toBuild)``
``MessageSigner* MessageValidatorFactory::BuildSigner(std::string toBuild)``
``
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
