
#ifndef _Sniffer_h__
#define _Sniffer_h__

#include "Define.h"
#include "Addresses.h"

#define PKT_VERSION 0x0301
#define SNIFFER_ID  15

using namespace ClientAddresses;

typedef struct {
    void* vTable;
    BYTE* buffer;
    DWORD base;
    DWORD alloc;
    DWORD size;
    DWORD read;
} CDataStore;

struct PacketInfo
{
    PacketInfo() : packetType(0), connectionId(0), opcodeSize(0), dataStore(nullptr) { }
    PacketInfo(DWORD64 PacketType, DWORD ConnectionId, WORD OpcodeSize, CDataStore* DataStore) :
        packetType(PacketType), connectionId(ConnectionId), opcodeSize(OpcodeSize),
        dataStore(DataStore)
    {
    }

    DWORD64 packetType;
    DWORD connectionId;
    WORD opcodeSize;
    CDataStore* dataStore;
};

class Sniffer
{
public:
    static Sniffer* instance()
    {
        static Sniffer instance;
        return &instance;
    }

    static void Stop() { m_stopEvent = true; }
    static bool IsStopped() { return m_stopEvent; }

    void InitSnifferInfo(std::string& DllPath, Addresses* addresses)
    {
        m_dllPath  = DllPath;
        m_fileDump = 0x0;
        m_addresses = addresses;
    }

    void SetBuild(int build) { m_build = build; }

    void SetLocale(std::string locale) { m_locale = locale; }
    std::string GetLocale();

    bool InitHooks();

    void DumpPacket(PacketInfo const& info);
    void CloseFileDump()
    {
        if (m_fileDump)
            fclose(m_fileDump);
    }

    FILE* GetFileDump() const { return m_fileDump; }
    const std::string& GetDLLPath() { return m_dllPath; }

public:
    DWORD GetBuild() { return m_build; }
    Expansions GetExpansion() { return m_expansion; }
    Expansions FindExpansion(DWORD build);

    void SetTestClient() { m_isTestClient = true; }
    bool IsTestClient() { return m_isTestClient; }

    Addresses const* GetAddresses() const { return m_addresses; }

    void SetHandle(HANDLE handle) { m_handle = handle; }
    HANDLE& GetHandle() { return m_handle; }
private:
    Sniffer();
    ~Sniffer();

    std::string m_dllPath;;
    std::string m_locale;
    int m_build;
    HANDLE m_handle;

    bool m_isTestClient;
    Expansions m_expansion;

    unsigned int GetOpcodeFromParam(char* param);

private:

    static std::atomic<bool> m_stopEvent;

    std::mutex dumpMutex;
    FILE* m_fileDump;

    Addresses* m_addresses;
};

#define sSniffer Sniffer::instance()

#endif