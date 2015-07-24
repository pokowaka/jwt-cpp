# The name of our project is "HELLO". CMakeLists files in this project can 
# refer to the root source directory of the project as ${HELLO_SOURCE_DIR} and 
# to the root binary directory of the project as ${HELLO_BINARY_DIR}. 
CMAKE_MINIMUM_REQUIRED (VERSION 2.8 FATAL_ERROR) 
PROJECT (JWT)

SET (TOOLS_DIRECTORY ${JWT_SOURCE_DIR}/tools)
INCLUDE (CheckFunctionExists)

LIST (APPEND CMAKE_MODULE_PATH "${TOOLS_DIRECTORY}/cmake/rpavlik")
LIST (APPEND CMAKE_MODULE_PATH "${TOOLS_DIRECTORY}/cmake")
LIST (APPEND CMAKE_MODULE_PATH "${TOOLS_DIRECTORY}/cmake/doxygen")
INCLUDE(GetGitRevisionDescription)
INCLUDE(cpplint)
INCLUDE(CodeCoverage)
INCLUDE(UseDoxygen)

get_git_head_revision(GIT_REFSPEC GIT_SHA1)
git_get_exact_tag(GIT_TAG)


MESSAGE ("Git version: ${GIT_SHA1}")
if (GIT_TAG)
    MESSAGE ("Git tag: ${GIT_TAG}")
ELSE ()
    MESSAGE ("Building untagged branch")
    SET (GIT_TAG "untagged")
ENDIF (GIT_TAG)


OPTION(ENABLE_GPERF_TOOLS  "Enable google perftools [default: OFF]" OFF)
OPTION(ENABLE_DOC          "Enable documentation    [default: ON]" ON)


set(JWT_INSTALL_LIB_DIR       lib CACHE PATH "Installation directory for libraries")
set(JWT_INSTALL_BIN_DIR       bin CACHE PATH "Installation directory for executables")
set(JWT_INSTALL_INCLUDE_DIR   include CACHE PATH "Installation directory for header files")

#
# Compiler SETtings
#
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
IF(CMAKE_BUILD_TYPE MATCHES "Debug")
  MESSAGE ("Setting debug flags")
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -fprofile-arcs -ftest-coverage")
  SET(CMAKE_C_FLAGS "-g -O0 -fprofile-arcs -ftest-coverage")
  INCLUDE_DIRECTORIES ("/usr/local/include/valgrind")
  IF (NOT ${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    LINK_LIBRARIES(gcov)
  ELSE()
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-optimize-sibling-calls")
  ENDIF ()
ENDIF(CMAKE_BUILD_TYPE MATCHES "Debug")


# Jansson
MESSAGE ("-- Looking for jansson")
UNSET(JANSSON)
FIND_LIBRARY (JANSSON NAMES jansson)
If (JANSSON)
    MESSAGE ("-- Jannson Already Available ${JANSSON}")
ELSE (JANSSON)
    MESSAGE ("-- Missing jansson, building locally")
    # We are not really interested in the debug build of jannson
    SET (CMAKE_C_FLAGS_DEBUG "-O3" CACHE STRING "Optimize a lot")
    SET (JANSEN_EXAMPLES OFF CACHE BOOL "No samples")
    SET (JANSSON_BUILD_DOCS OFF CACHE BOOL "No docs")
    SET (JANSSON_COVERALLS_UPLOAD OFF CACHE BOOL "No coveralls")
    SET (JANSSON_WITHOUT_TESTS ON CACHE BOOL "No tests")
    ADD_SUBDIRECTORY (${JWT_SOURCE_DIR}/ext/jansson)
ENDIF (JANSSON)

# Gperf tools
IF(ENABLE_GPERF_TOOLS MATCHES "ON")
    MESSAGE("Looking for gperftools")
    FIND_PATH(GPERF_INCLUDE google/profiler.h PATHS /opt/include
        /usr/include
        /usr/local/include
        DOC "Path where google perftools includes can be found")
    INCLUDE_DIRECTORIES("${GPERF_INCLUDE}")
    FIND_LIBRARY(GPERF_LIBRARY NAMES profiler PATH_SUFFIXES lib64 lib
        PATHS
        ~/Library/Frameworks
        /Library/Frameworks
        /usr/local
        /usr
        /sw
        /opt/local
        /opt/csw
        /opt
        DOC "Path where the gperf library can be found")
    IF(NOT GPERF_LIBRARY)
        MESSAGE(FATAL_ERROR "gperf tools support is enabled but not found in system")
    ENDIF(NOT GPERF_LIBRARY)
    SET(TCMALLOC_NAMES ${TCMALLOC_NAMES} tcmalloc)
    FIND_LIBRARY(TCMALLOC_LIBRARY
        NAMES ${TCMALLOC_NAMES}
        PATHS
        ~/Library/Frameworks
        /Library/Frameworks
        /usr/local
        /usr
        /sw
        /opt/local
        /opt/csw
        /opt
        DOC "Path where the gperf library can be found")
    GET_FILENAME_COMPONENT(GPERF_PATH "${GPERF_LIBRARY}" PATH)
    LINK_DIRECTORIES("${GPERF_PATH}")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer")
    SET(WITH_GPERF_TOOLS 1)
ENDIF(ENABLE_GPERF_TOOLS MATCHES "ON")


# Search OpenSSL
FIND_PACKAGE(PkgConfig REQUIRED)
PKG_SEARCH_MODULE(OPENSSL REQUIRED openssl openssl>=1.0.2)

IF(OPENSSL_FOUND)
    INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIRS})
    MESSAGE(STATUS "Using OpenSSL ${OPENSSL_VERSION} - ${OPENSSL_LIBDIR} - ${OPENSSL_LIBRARY_DIRS}")
ELSE()
    # Error; with REQUIRED, pkg_search_module() will throw an error by it's own
ENDIF()

# General include directories
INCLUDE_DIRECTORIES (src/include/ src/include/private)
INCLUDE_DIRECTORIES ( ${JANSSON_INCLUDE_DIRS} )
LINK_DIRECTORIES (${OPENSSL_LIBRARY_DIRS})
ADD_SUBDIRECTORY (src)

#-------------------
# Test
#-------------------
ENABLE_TESTING (true)
ADD_SUBDIRECTORY (ext/gtest-1.7.0)
ADD_SUBDIRECTORY (test)
