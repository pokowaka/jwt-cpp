Jwt-cpp
=======

A C++ implementation of [JSON Web Token](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html). 

jwt-cpp is licensed under the [MIT license](http://opensource.org/licenses/mit-license.php); see LICENSE in the source distribution for details.

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

## Usage

We make use of [jansson](http://www.digip.org/jansson/) to create json payload.

```
  HS256Validator signer("secret!");
  json_ptr json(json_pack("{ss}", "name", "John Doe"));
  str_ptr str_token(JWT::Encode(&signers, json.get()));  
```

Validating tokens works as follows:

```
  // Use the expiration validator
  ExpValidator exp;

  // Decode and validate the token
  jwt_ptr token;
  try {
    token.reset(JWT::Decode(str_token.get(), &signer, &exp));
  } catch (TokenFormatError *tfe) {
    // Badly encoded token
    FAIL();
  }

  if (!token->IsValid()) {
    // Claim validators say token is invalid
  }

  if (!token->IsSigned()) {
    // JWT is not signed.
  }
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
