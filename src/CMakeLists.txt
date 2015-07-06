LINK_DIRECTORIES (${JWT-CPP_BINARY_DIR}/src/token) 


ADD_LIBRARY(jwt-cpp token/claimset.cpp token/jwt.cpp base64/base64.cpp)

TARGET_COMPILE_FEATURES(jwt-cpp PRIVATE cxx_delegating_constructors)
TARGET_LINK_LIBRARIES (jwt-cpp ${JANSSON_LIBRARY} ${CMAKE_DL_LIBS} ${SSL_LIBRARY})

IF(ENABLE_GPERF_TOOLS MATCHES "ON")
    TARGET_LINK_LIBRARIES(jwt-cpp profiler)
    TARGET_LINK_LIBRARIES(jwt-cpp tcmalloc)
ENDIF(ENABLE_GPERF_TOOLS MATCHES "ON")
