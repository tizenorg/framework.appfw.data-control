CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

SET(this_target "data-control")

SET(CMAKE_INSTALL_PREFIX /usr)
SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(LIBDIR "\${prefix}/lib")
SET(INCLUDEDIR "\${prefix}/include/appfw")
SET(VERSION_MAJOR 1)
SET(VERSION "${VERSION_MAJOR}.1")

## OUTPUT PATHS
SET(LIBRARY_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/cmake_build_tmp/output)

INCLUDE_DIRECTORIES (
	/usr/include
	/usr/include/appfw
	/usr/include/dlog
	/usr/include/glib-2.0
	/usr/lib/glib-2.0/include
	include
	)

SET (${this_target}_SOURCE_FILES
	src/data-control-map.c
	src/data-control-sql.c
	src/data-control-sql-cursor.c
	src/data-control-provider.c
	src/data-control-internal.c
)

SET(requires "dlog bundle glib-2.0 appsvc pkgmgr-info security-server")

INCLUDE(FindPkgConfig)
pkg_check_modules(${this_target} REQUIRED ${requires})
FOREACH(flag ${${this_target}_CFLAGS})
    SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(EXTRA_CFLAGS  "${EXTRA_CFLAGS} -Wall" )

## SET C COMPILER FLAGS
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -fPIC -Wall -Werror -fvisibility=hidden")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g")

## SET CPP COMPILER FLAGS
SET(CMAKE_CXX_FLAGS "${OSP_DEBUG_FLAGS} ${CMAKE_CXX_FLAGS} ${EXTRA_CFLAGS} ${OSP_COMPILER_FLAGS}")

IF("${ARCH}" STREQUAL "arm")
    ADD_DEFINITIONS("-DTARGET")
ENDIF("${ARCH}" STREQUAL "arm")

ADD_DEFINITIONS("-DPREFIX=\"${CMAKE_INSTALL_PREFIX}\"")
ADD_DEFINITIONS("-DSLP_DEBUG")
ADD_DEFINITIONS("-D_APPFW_FEATURE_DATA_CONTROL")

## Create Library
ADD_LIBRARY (${this_target} SHARED ${${this_target}_SOURCE_FILES})

## SET LINKER FLAGS
SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed -Wl,--rpath=/usr/lib")
TARGET_LINK_LIBRARIES(${this_target} ${${this_target}_LDFLAGS})

SET_TARGET_PROPERTIES(${this_target}
	PROPERTIES
	VERSION ${FULLVER}
	SOVERSION ${MAJORVER}
	CLEAN_DIRECT_OUTPUT 1
	)


# pkgconfig file
CONFIGURE_FILE(${this_target}.pc.in ${CMAKE_SOURCE_DIR}/${this_target}.pc @ONLY)
INSTALL(FILES ${CMAKE_SOURCE_DIR}/${this_target}.pc DESTINATION lib/pkgconfig)

INSTALL(TARGETS ${this_target} DESTINATION lib)

INSTALL(DIRECTORY ${CMAKE_SOURCE_DIR}/include/ DESTINATION include/appfw FILES_MATCHING PATTERN "*.h")

INSTALL(DIRECTORY ${LIBRARY_OUTPUT_PATH}/ DESTINATION lib
		FILES_MATCHING PATTERN "*.so*"
		PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ
                    GROUP_EXECUTE GROUP_READ
                    WORLD_EXECUTE WORLD_READ)
