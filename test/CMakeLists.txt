INCLUDE_DIRECTORIES (${JWT_SOURCE_DIR}/ext)
INCLUDE_DIRECTORIES (${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})

ADD_EXECUTABLE (validators_test validators/validators_test.cpp)
ADD_EXECUTABLE (validators_factory_test validators/validators_factory_test.cpp)
ADD_EXECUTABLE (claim_validators_test validators/claim_validators_test.cpp)
ADD_EXECUTABLE (claim_validators_factory_test validators/claim_validators_factory_test.cpp)
ADD_EXECUTABLE (base64_test base64/base64_test.cpp)
ADD_EXECUTABLE (token_test token/token_test.cpp)
ADD_EXECUTABLE (sample token/sample.cpp)

SET(TESTS
  validators_test
  validators_factory_test
  claim_validators_test
  claim_validators_factory_test
  base64_test
  token_test
  sample
)

FOREACH(TEST ${TESTS} )
    SET_PROPERTY(TARGET ${TEST} PROPERTY CXX_STANDARD 11)
    TARGET_LINK_LIBRARIES (${TEST} jwt gtest_main)
    ADD_TEST (${TEST} ${TEST})
    IF(UNIX)
        SETUP_TARGET_FOR_COVERAGE("cov_${TEST}" ${TEST} coverage)
    ENDIF(UNIX)
ENDFOREACH(TEST ${TESTS} )

IF(UNIX AND ENABLE_GPERF_TOOLS MATCHES "ON")
    TARGET_LINK_LIBRARIES(base64_test profiler)
    TARGET_LINK_LIBRARIES(base64_test tcmalloc)
ENDIF(UNIX AND ENABLE_GPERF_TOOLS MATCHES "ON")

ADD_EXECUTABLE (all_tests all.cpp)
SET_PROPERTY(TARGET all_tests PROPERTY CXX_STANDARD 11)
TARGET_LINK_LIBRARIES (all_tests jwt gtest_main)
IF(UNIX)
    SETUP_TARGET_FOR_COVERAGE("cov_all_tests" all_tests coverage)
ENDIF(UNIX)