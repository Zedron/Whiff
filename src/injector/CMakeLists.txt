file(GLOB sources_localdir *.cpp *.h)

set(injector_SRCS
  ${injector_SRCS}
  ${sources_localdir}
)

include_directories(
  ${CMAKE_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/src/shared
)

GroupSources(${CMAKE_CURRENT_SOURCE_DIR})

add_executable(injector
  ${injector_SRCS}
)

set_target_properties(injector PROPERTIES LINK_FLAGS "${injector_LINK_FLAGS}")

target_link_libraries(injector
  shared
  shlwapi
  version
)

IF(PLATFORM EQUAL 64)
  set_target_properties(injector PROPERTIES OUTPUT_NAME Whiff-64)
ELSE()
  set_target_properties(injector PROPERTIES OUTPUT_NAME Whiff)
ENDIF()

install(TARGETS injector DESTINATION "${CMAKE_INSTALL_PREFIX}")

