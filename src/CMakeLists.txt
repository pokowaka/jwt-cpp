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
  SET(JWT_SRC ${JWT_SRC} ${SRC} )
ENDFOREACH( DIR ${JWT_SOURCE_DIRS} )

FILE(GLOB JWT_HDR include/jwt/*.h include/jwt/*.h??)


ADD_LIBRARY(jwt ${JWT_SRC} ${JWT_HDR})
IF (OPENSSL_LIBRARY_DIRS)
    #if user defined OPENSSL_INCLUDE_DIRS, OPENSSL_LIBRARY_DIRS and OPENSSL_LIBRARIES
    TARGET_LINK_LIBRARIES (jwt ${OPENSSL_LIBRARIES})
ELSE()
    #The default and preferred way
    TARGET_LINK_LIBRARIES(jwt OpenSSL::SSL OpenSSL::Crypto)
ENDIF()
IF(UNIX)
    #libdl is needed by OpenSSL, but is not a dependency of OpenSSL::Crypto
    TARGET_LINK_LIBRARIES(jwt dl)
    SET_PROPERTY(TARGET jwt PROPERTY CXX_STANDARD 11)
ENDIF(UNIX)

IF(UNIX AND ENABLE_GPERF_TOOLS MATCHES "ON")
    TARGET_LINK_LIBRARIES(jwt-cpp profiler)
    TARGET_LINK_LIBRARIES(jwt-cpp tcmalloc)
ENDIF(UNIX AND ENABLE_GPERF_TOOLS MATCHES "ON")

target_include_directories(jwt PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include/>  # <prefix>/include
)

SET_TARGET_PROPERTIES(jwt PROPERTIES PUBLIC_HEADER "${JWT_HDR}")
# Install targets.
INSTALL(TARGETS jwt
        EXPORT JwtTargets
        LIBRARY DESTINATION "${JWT_INSTALL_LIB_DIR}" COMPONENT lib
        ARCHIVE DESTINATION "${JWT_INSTALL_LIB_DIR}" COMPONENT lib
        PUBLIC_HEADER DESTINATION "${JWT_INSTALL_INCLUDE_DIR}/jwt" COMPONENT lib)

ADD_STYLE_CHECK_TARGET(lint "${JWT_SRC}")

set_property(TARGET jwt PROPERTY VERSION ${JWT_VERSION})
set_property(TARGET jwt PROPERTY SOVERSION ${JWT_VERSION_MAJOR})
set_property(TARGET jwt PROPERTY DEBUG_POSTFIX d)

#Some boiler plate code to generate the cmake module files for Jwt
install(EXPORT JwtTargets
    FILE JwtTargets.cmake
    NAMESPACE Jwt::
    DESTINATION ${JWT_INSTALL_LIB_DIR}/cmake/Jwt
)
include(CMakePackageConfigHelpers)
write_basic_package_version_file("JwtConfigVersion.cmake"
    VERSION ${JWT_VERSION}
    COMPATIBILITY SameMajorVersion
)

file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/JwtConfig.cmake" "
include(\"\${CMAKE_CURRENT_LIST_DIR}/JwtTargets.cmake\")
")

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/JwtConfigVersion.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/JwtConfig.cmake
    DESTINATION ${JWT_INSTALL_LIB_DIR}/cmake/Jwt
)
