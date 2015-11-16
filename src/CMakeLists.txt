add_subdirectory(shared)

if(INJECTOR)
  add_subdirectory(injector)
endif(INJECTOR)

if(SNIFFER)
  add_subdirectory(sniffer)
endif(SNIFFER)
