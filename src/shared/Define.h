#include <stdint.h>
#include <Windows.h>
#include <cstdio>
#include <set>
#include <vector>
#include <unordered_map>
#include <map>
#include <atomic>
#include <mutex>
#include <thread>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <regex>

#if defined(_WIN64)
  typedef uint64_t ADDRESS;
  #define WOW_OFFSET 0x0000000140000000
#else
  typedef uint32_t ADDRESS;
  #define WOW_OFFSET 0x00400000
#endif

#define EXE_REBASE(x) (ADDRESS)((x) - WOW_OFFSET + (ADDRESS)GetModuleHandle(NULL))
#define STATIC_REBASE(x) (ADDRESS)((x) + WOW_OFFSET - (ADDRESS)GetModuleHandle(NULL))

#define CMSG 0x47534D43 // client to server, CMSG
#define SMSG 0x47534D53 // server to client, SMSG

