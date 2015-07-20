SET(JWT_SOURCE_DIRS
  jwt
  base64
  validators
  validators/claims
  util
  jwe
)

FOREACH( DIR ${JWT_SOURCE_DIRS} )
  AUX_SOURCE_DIRECTORY(${DIR} JWT_SRC)
	FILE(GLOB SRC ${DIR}/*.h )
  SET(JWT_SRC ${JWT_SRC} ${SRC} )
ENDFOREACH( DIR ${JWT_SOURCE_DIRS} )

ADD_LIBRARY(jwt ${JWT_SRC})
TARGET_LINK_LIBRARIES (jwt jansson ${OPENSSL_LIBRARIES})
SET_PROPERTY(TARGET jwt PROPERTY CXX_STANDARD 11)

IF(ENABLE_GPERF_TOOLS MATCHES "ON")
    TARGET_LINK_LIBRARIES(jwt-cpp profiler)
    TARGET_LINK_LIBRARIES(jwt-cpp tcmalloc)
ENDIF(ENABLE_GPERF_TOOLS MATCHES "ON")

################################################################################
#
# CPP lint check target
#
################################################################################
ADD_STYLE_CHECK_TARGET(lint "${JWT_SRC}")

