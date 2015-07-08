INCLUDE_DIRECTORIES (${JWT-CPP_SOURCE_DIR}/ext)
INCLUDE_DIRECTORIES (${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})


ADD_EXECUTABLE (claimset_test token/claimset_test.cpp)
ADD_EXECUTABLE (jws_test token/jws_test.cpp)
ADD_EXECUTABLE (validators_test validators/validators_test.cpp)
ADD_EXECUTABLE (base64_test base64/base64_test.cpp)
ADD_EXECUTABLE (token_test token/token_test.cpp)

TARGET_LINK_LIBRARIES (claimset_test jwt-cpp gtest_main)
TARGET_LINK_LIBRARIES (jws_test jwt-cpp gtest_main ${OPENSSL_LIBRARIES})
TARGET_LINK_LIBRARIES (validators_test jwt-cpp gtest_main ${OPENSSL_LIBRARIES})
TARGET_LINK_LIBRARIES (base64_test jwt-cpp gtest_main)
TARGET_LINK_LIBRARIES (token_test jwt-cpp gtest_main)

IF(ENABLE_GPERF_TOOLS MATCHES "ON")
    TARGET_LINK_LIBRARIES(base64_test profiler)
    TARGET_LINK_LIBRARIES(base64_test tcmalloc)
ENDIF(ENABLE_GPERF_TOOLS MATCHES "ON")

ADD_TEST (claimset_test claimset_test)
ADD_TEST (jws_test jws_test)
ADD_TEST (validators_test validators_test)
ADD_TEST (base64_test base64_test)
ADD_TEST (token_test token_test)

#
# Run test coverage
#
IF (COVERAGE)
    IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
        ADD_CUSTOM_TARGET (coverage
            COMMAND ./tools/gcovr -x -r . -e ext -e test > coverage.xml
            WORKING_DIRECTORY ${JWT-CPP_SOURCE_DIR}
            COMMENT "Running code coverage check")
    ELSE ()
        ADD_CUSTOM_TARGET (coverage
            COMMENT "Code coverage not supported on this platform (must be using GCC, this platform uses ${CMAKE_CXX_COMPILER_ID})")
    ENDIF ()
ENDIF ()
