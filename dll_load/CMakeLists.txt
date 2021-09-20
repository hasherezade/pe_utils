cmake_minimum_required (VERSION 2.8)

project ( dll_load )

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

option(DLL_LOAD_PAUSE_ON_FINISH "dll_load: pause after execution" ON)

if(DLL_LOAD_PAUSE_ON_FINISH)
    add_compile_definitions(PAUSE_AFTER)
endif()

set (srcs
	main.cpp
)

# general headers - they will be used for both EXE and DLL:
set (hdrs
#put your headers here
)

set (rsrc
#put your resources here
)

add_executable ( ${PROJECT_NAME} ${exe_hdrs} ${srcs} ${rsrc} main.cpp )

INSTALL( TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX} COMPONENT ${PROJECT_NAME} )
