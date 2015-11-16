# output generic information
if( UNIX )
  message("")
  message("* Whiff buildtype      : ${CMAKE_BUILD_TYPE}")
endif()

message("")

# output information about installation-directories and locations

message("* Install whiff to       : ${CMAKE_INSTALL_PREFIX}")
message("")

# Show infomation about the options selected during configuration

if( INJECTOR )
  message("* Build injector         : Yes (default)")
else()
  message("* Build injector         : No")
endif()

if( SNIFFER )
  message("* Build sniffer          : Yes (default)")
else()
  message("* Build sniffer          : No")
endif()

message("")

