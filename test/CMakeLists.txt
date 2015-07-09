INCLUDE_DIRECTORIES (${JWT_SOURCE_DIR}/ext)
INCLUDE_DIRECTORIES (${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})

ADD_EXECUTABLE (jws_test token/jws_test.cpp)
ADD_EXECUTABLE (validators_test validators/validators_test.cpp)
ADD_EXECUTABLE (claim_validators_test validators/claim_validators_test.cpp)
ADD_EXECUTABLE (base64_test base64/base64_test.cpp)
ADD_EXECUTABLE (token_test token/token_test.cpp)

SET(TESTS
  jws_test
  validators_test
  claim_validators_test
  base64_test
  token_test
)

FOREACH(TEST ${TESTS} )
    SET_PROPERTY(TARGET ${TEST} PROPERTY CXX_STANDARD 11)
    TARGET_LINK_LIBRARIES (${TEST} jwt gtest_main)
    ADD_TEST (${TEST} ${TEST})
    SETUP_TARGET_FOR_COVERAGE("cov_${TEST}" ${TEST} coverage)
ENDFOREACH(TEST ${TESTS} )

IF(ENABLE_GPERF_TOOLS MATCHES "ON")
    TARGET_LINK_LIBRARIES(base64_test profiler)
    TARGET_LINK_LIBRARIES(base64_test tcmalloc)
ENDIF(ENABLE_GPERF_TOOLS MATCHES "ON")

ADD_EXECUTABLE (all_tests all.cpp)
SET_PROPERTY(TARGET all_tests PROPERTY CXX_STANDARD 11)
TARGET_LINK_LIBRARIES (all_tests jwt gtest_main)
SETUP_TARGET_FOR_COVERAGE("cov_all_tests" all_tests coverage)
