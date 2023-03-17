cmake_minimum_required ( VERSION 3.0 )

project ( pe_check )

# libs
# modules:
set ( M_PARSER "libpeconv/libpeconv" )

# modules paths:
set (PECONV_DIR "${CMAKE_SOURCE_DIR}/${M_PARSER}" CACHE PATH "PEConv main path")
add_subdirectory ( ${PECONV_DIR} )
set ( PECONV_LIB $<TARGET_FILE:libpeconv> CACHE PATH "PEConvLib library path" )

# Add sub-directories
#
add_subdirectory ( pe_check )
add_subdirectory ( dll_load )
add_subdirectory ( kdb_check )
add_subdirectory ( syscall_extractor )