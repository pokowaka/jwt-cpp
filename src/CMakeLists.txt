ADD_LIBRARY(jwt-cpp
  validators/digestvalidator.cpp
  validators/nonevalidator.cpp
  token/jwsverifier.cpp
  token/claimset.cpp
  base64/base64.cpp token/Token.cpp token/Token.h)

TARGET_LINK_LIBRARIES (jwt-cpp ${JANSSON_LIBRARY} ${OPENSSL_LIBRARIES})
SET_PROPERTY(TARGET jwt-cpp PROPERTY CXX_STANDARD 11)

IF(ENABLE_GPERF_TOOLS MATCHES "ON")
    TARGET_LINK_LIBRARIES(jwt-cpp profiler)
    TARGET_LINK_LIBRARIES(jwt-cpp tcmalloc)
ENDIF(ENABLE_GPERF_TOOLS MATCHES "ON")
