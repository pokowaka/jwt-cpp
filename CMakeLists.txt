CMAKE_MINIMUM_REQUIRED (VERSION 3.2 FATAL_ERROR)
PROJECT (JWT VERSION 1.1.0)

SET (TOOLS_DIRECTORY ${JWT_SOURCE_DIR}/tools)
INCLUDE (CheckFunctionExists)

LIST (APPEND CMAKE_MODULE_PATH "${TOOLS_DIRECTORY}/cmake")
LIST (APPEND CMAKE_MODULE_PATH "${TOOLS_DIRECTORY}/cmake/rpavlik")
LIST (APPEND CMAKE_MODULE_PATH "${TOOLS_DIRECTORY}/cmake/doxygen")

INCLUDE(GetGitRevisionDescription)
INCLUDE(cpplint)
INCLUDE(UseDoxygen)

get_git_head_revision(GIT_REFSPEC GIT_SHA1)
git_get_exact_tag(GIT_TAG)

MESSAGE ("JWT version ${JWT_VERSION}")
MESSAGE ("Git version: ${GIT_SHA1}")
if (GIT_TAG)
    MESSAGE ("Git tag: ${GIT_TAG}")
ELSE ()
    MESSAGE ("Building untagged branch")
    SET (GIT_TAG "untagged")
ENDIF (GIT_TAG)

OPTION(ENABLE_GPERF_TOOLS  "Enable google perftools [default: OFF]" OFF)
OPTION(ENABLE_CLANG_TIDY   "Enable clang tidy [default: OFF]" OFF)
OPTION(ENABLE_COVERAGE     "Enable coder coverage [default: OFF]" OFF)
OPTION(ENABLE_DOC          "Enable documentation    [default: ON]" ON)
OPTION(ENABLE_TESTS        "Enable tests [default: ON]" ON)
OPTION(BUILD_SHARED_LIBS   "Build all libraries as shared library [default: OFF]" OFF)

set(JWT_INSTALL_LIB_DIR       lib CACHE PATH "Installation directory for libraries")
set(JWT_INSTALL_BIN_DIR       bin CACHE PATH "Installation directory for executables")
set(JWT_INSTALL_INCLUDE_DIR   include CACHE PATH "Installation directory for header files")

#
# Compiler Settings
#
IF(UNIX)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
    IF(ENABLE_COVERAGE MATCHES "ON")
        INCLUDE(CodeCoverage)
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0")
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage") # enabling coverage
        INCLUDE_DIRECTORIES ("/usr/local/include/valgrind")
    ENDIF(ENABLE_COVERAGE MATCHES "ON")
ENDIF(UNIX)

# Gperf tools
IF(UNIX AND ENABLE_GPERF_TOOLS MATCHES "ON")
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
ENDIF(UNIX AND ENABLE_GPERF_TOOLS MATCHES "ON")


# Run clang-tidy if needed.
IF(ENABLE_CLANG_TIDY MATCHES "ON")
    FIND_PROGRAM(CLANG_TIDY_EXE NAMES "clang-tidy" DOC "Path to clang-tidy executable")
    IF(NOT CLANG_TIDY_EXE)
        MESSAGE(STATUS "clang-tidy not found.")
    ELSE()
        MESSAGE(STATUS "clang-tidy found: ${CLANG_TIDY_EXE}")
        SET(DO_CLANG_TIDY "${CLANG_TIDY_EXE}" "-checks=*")
    ENDIF()
ENDIF()

# OpenSSL
IF (OPENSSL_INCLUDE_DIRS AND OPENSSL_LIBRARY_DIRS AND OPENSSL_LIBRARIES)
    MESSAGE(STATUS "Using provided OpenSSL")
    MESSAGE(STATUS "  Include dir: ${OPENSSL_INCLUDE_DIRS}")
    MESSAGE(STATUS "  Library dirs: ${OPENSSL_LIBRARY_DIRS}")
    MESSAGE(STATUS "  Libraries: ${OPENSSL_LIBRARIES}")
ELSE()
    MESSAGE(STATUS "No version of OpenSSL provided, searching for v1.1.0")
    IF(APPLE)
        # If it doesn't go to any Cellar it will not work.
        EXECUTE_PROCESS(COMMAND bash -c "brew info openssl@1.1 | grep Cellar | sed 's/ .*//' | tr -d '\r\n'" OUTPUT_VARIABLE MAC_SSL_ROOT)
        SET(OPENSSL_INCLUDE_DIRS ${MAC_SSL_ROOT}/include)
        SET(OPENSSL_LIBRARY_DIRS ${MAC_SSL_ROOT}/lib)
        SET(OPENSSL_LIBRARIES "-lcrypto")

        IF (NOT EXISTS ${OPENSSL_INCLUDE_DIRS})
            MESSAGE(FATAL_ERROR "Cannot find ${MAC_SSL_ROOT}, please run brew install openssl@1.1")
        ENDIF()
    ELSEIF(UNIX)
        FIND_PACKAGE(PkgConfig REQUIRED)
        PKG_SEARCH_MODULE(OPENSSL REQUIRED openssl openssl>=1.1.0)
        IF(OPENSSL_FOUND)
            MESSAGE(STATUS "Using OpenSSL ${OPENSSL_VERSION} - ${OPENSSL_LIBDIR} - ${OPENSSL_LIBRARY_DIRS}")
        ELSE()
            # Error; with REQUIRED, pkg_search_module() will throw an error by it's own
        ENDIF()
    ELSE(APPLE)
        SET(OPENSSL_INCLUDE_DIRS ${OPENSSL_INCLUDE_DIRS})
        SET(OPENSSL_LIBRARY_DIRS ${OPENSSL_LIBRARY_DIRS})
        SET(OPENSSL_LIBRARIES "libcrypto libssl")
        IF(NOT OPENSSL_INCLUDE_DIRS OR NOT OPENSSL_LIBRARY_DIRS)
            MESSAGE(FATAL_ERROR "Set path to openssl include and library dirs: -DOPENSSL_INCLUDE_DIRS=path -DOPENSSL_LIBRARY_DIRS=path")
        ENDIF()
    ENDIF(APPLE)
ENDIF()


# General include directories
INCLUDE_DIRECTORIES(src/include/ src/include/private)
INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIRS})
LINK_DIRECTORIES (${OPENSSL_LIBRARY_DIRS})
ADD_SUBDIRECTORY (src)

#-------------------
# Test
#-------------------
IF(ENABLE_TESTS MATCHES "ON")
    ENABLE_TESTING(true)
    IF (MSVC)
        SET(gtest_force_shared_crt ON CACHE BOOL "Force gtest to build with shared crt")
    ENDIF(MSVC)
    ADD_SUBDIRECTORY(ext/gtest-1.7.0)
    ADD_SUBDIRECTORY(test)
ENDIF(ENABLE_TESTS MATCHES "ON")

IF (BUILD_SHARED_LIBS)
    MESSAGE("Will build JWT as a shared library")
ENDIF()
