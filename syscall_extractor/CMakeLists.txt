cmake_minimum_required (VERSION 3.0)

project ( syscall_extract )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

# include libpeconv headers:
include_directories ( ${PECONV_DIR}/include )

set (srcs
	main.cpp
	util.cpp
)

# general headers - they will be used for both EXE and DLL:
set (hdrs
	util.h
)

set (rsrc
#put your resources here
)

add_executable ( ${PROJECT_NAME} ${exe_hdrs} ${srcs} ${rsrc} main.cpp )

# link with libpeconv.lib
target_link_libraries ( ${PROJECT_NAME} ${PECONV_LIB} )

#dependencies:
add_dependencies( ${PROJECT_NAME} libpeconv )

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
