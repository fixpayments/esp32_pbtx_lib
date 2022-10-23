cmake_minimum_required(VERSION 3.20)

idf_component_register(
  SRCS
  "pbtx_client.c"
  "esp32_pbtx_signature_provider.c"
  "nanopb/pb_common.c"
  "nanopb/pb_encode.c"
  INCLUDE_DIRS include
  PRIV_INCLUDE_DIRS nanopb
  REQUIRES mbedtls nvs_flash)

add_subdirectory(pbtx.pb)

