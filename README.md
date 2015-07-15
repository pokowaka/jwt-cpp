Jwt-cpp
=======

A C++ implementation of [JSON Web Token](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html). 

jwt-cpp is licensed under the [MIT license](http://opensource.org/licenses/mit-license.php); see LICENSE in the source distribution for details.

Currently it supports the following:

Sign, Verify JWS:

- HS256
- HS384
- HS512
- *none*

Payload validators:

- iss check
- sub check
- aud check
- exp check
- nbf check
- iat check

## Usage

We make use of (jansson)[http://www.digip.org/jansson/] to create json payload.

```
  HS256Validator validator("secret");
  json_t* payload = json_pack("{ss, ss, sb}", "sub", "1234567890", "name", "John Doe", "admin", true);
  char* Token::Encode(payload, &validator));

  delete token;
  json_decref(payload);
```

Validating tokens works as follows:

```
  HS256Validator validator("secret");
  JwsVerifier verifier(&validator);

  const char* const accepted[] = { "1234567890", "bar" };
  SubValidator sub(accepted, 2);

  char* tokenstr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
  Token* token = Token::Parse(tokenstr, strlen(tokenstr));

  if (token && token->VerifySignature(verifier) && token->VerifyClaims(sub)) {
    printf("Valid token, with acceptable claims\n");
  }

  delete token;
```


## Compilation and Installation

Jwt-cpp uses the [CMake](http://www.cmake.org/) cross platform build tools to build. Once you have installed the proper dependencies you can do the following:

For release:

```
mkdir release 
cd release 
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

For debug:
```
mkdir debug 
cd debug 
cmake -DCMAKE_BUILD_TYPE=Debug ..
make
```



### Dependencies in linux

You will need to install the following dependencies:
```
sudo apt-get install libssl-dev cmake lcov
```


### How to build in Mac OS

First make sure you have the proper dependencies. The easiest way is to use [Homebrew](http://brew.sh/).

```
brew install cmake lcov
brew upgrade openssl
brew link --force openssl
pkg-config --modversion openssl
```
