cmake_minimum_required(VERSION 3.20)

idf_component_register(
  SRCS
  "pbtx_client.c"
  "nanopb/pb_common.c"
  "nanopb/pb_encode.c"  
  INCLUDE_DIRS include
  PRIV_INCLUDE_DIRS nanopb
  REQUIRES mbedtls)

add_subdirectory(pbtx.pb)

