set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../nanopb/extra)
find_package(Nanopb REQUIRED)


NANOPB_GENERATE_CPP(PROTO_SRCS PROTO_HDRS pbtx.proto)

message ("PROTO_SRCS = ${PROTO_SRCS}")
message ("PROTO_HDRS = ${PROTO_HDRS}")

target_include_directories(${COMPONENT_LIB} PUBLIC ${NANOPB_INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR})

add_custom_target(pbtx_pb DEPENDS ${PROTO_SRCS})
add_dependencies(${COMPONENT_LIB} pbtx_pb)


