idf_component_register(INCLUDE_DIRS "include")

add_prebuilt_library(oqs "${CMAKE_CURRENT_LIST_DIR}/lib/liboqs.a")

target_link_libraries(${COMPONENT_LIB} INTERFACE oqs)

# Expose headers to dependents
target_include_directories(${COMPONENT_LIB} INTERFACE "${CMAKE_CURRENT_LIST_DIR}/include")