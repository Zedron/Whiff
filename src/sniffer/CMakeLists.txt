file(GLOB_RECURSE sources_Opcodes Opcodes/*.cpp Opcodes/*.h)
file(GLOB_RECURSE sources_Commands Commands/*.cpp Commands/*.h)
file(GLOB_RECURSE sources_HexSearcher HexSearcher/*.cpp HexSearcher/*.h)
file(GLOB sources_localdir *.cpp *.h *.hpp)

set(sniffer_STAT_SRCS
  ${sniffer_STAT_SRCS}
  ${sources_Opcodes}
  ${sources_Commands}
  ${sources_HexSearcher}
  ${sources_localdir}
)

include_directories(
  ${CMAKE_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/dep/MologieDetours
  ${CMAKE_SOURCE_DIR}/dep/MologieDetours/src
  ${CMAKE_SOURCE_DIR}/dep/MologieDetours/include
  ${CMAKE_SOURCE_DIR}/src/shared
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/Commands
  ${CMAKE_CURRENT_SOURCE_DIR}/HexSearcher
  ${CMAKE_CURRENT_SOURCE_DIR}/Opcodes
)

add_library(sniffer SHARED
  ${sniffer_STAT_SRCS}
)

IF(PLATFORM EQUAL 64)
  set_target_properties(sniffer PROPERTIES OUTPUT_NAME Whiff-64)
ELSE()
  set_target_properties(sniffer PROPERTIES OUTPUT_NAME Whiff)
ENDIF()

target_link_libraries(sniffer
  shared
  shlwapi
  version
  MologieDetours
)

