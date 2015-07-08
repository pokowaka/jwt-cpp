jwt-cpp
=======

JSON Webtokens in C++


## How to build in Mac OS

First make sure you have the proper dependencies.

```
brew install jansson cmake
brew upgrade openssl
brew link --force openssl
pkg-config --modversion openssl
```

next create the needed build scripts:

```
mkdir build
cd build
cmake ..
make
make test
```

or if you like to work in XCode

```
mkdir osx
cd osx
cmake -G Xcode ..
```

You should now be able to open JWT-CPP.xcodeproj
