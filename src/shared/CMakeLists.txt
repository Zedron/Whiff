file(GLOB sources_localdir *.cpp *.h)

#
# Build shared sourcelist
#

set(shared_STAT_SRCS
  ${shared_STAT_SRCS}
  ${sources_localdir}
)

GroupSources(${CMAKE_CURRENT_SOURCE_DIR})

add_library(shared STATIC
  ${shared_STAT_SRCS}
)
target_link_libraries(shared
  shlwapi
  version
)