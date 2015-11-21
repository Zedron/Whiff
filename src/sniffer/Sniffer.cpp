#include "Sniffer.h"
#include "Hooks.h"
#include "OpcodeMgr.h"

std::atomic<bool> Sniffer::m_stopEvent(false);

Sniffer::Sniffer() : m_isTestClient(false), m_expansion(EXPANSION_NONE) { }

Sniffer::~Sniffer() { }

bool Sniffer::InitHooks()
{
    return Trampolines::Init();
}

std::string Sniffer::GetLocale()
{
    if (!m_locale.empty())
        return m_locale;

    std::string locale = Trampolines::GetLocale();
    if (!locale.empty())
        printf("Detected client locale: %s\n", locale.c_str());
    else
        printf("Client locale not detected\n");

    SetLocale(locale);
    return locale;
}

void Sniffer::DumpPacket(PacketInfo const& info)
{
    DWORD packetOpcode = info.opcodeSize == 4
        ? *(DWORD*)info.dataStore->buffer
        : *(WORD*)info.dataStore->buffer;

    if (!sOpcodeMgr->ShouldShowOpcode(packetOpcode, info.packetType))
        return;

    dumpMutex.lock();
    // gets the time
    time_t rawTime;
    time(&rawTime);

    DWORD tickCount = GetTickCount();

    DWORD optionalHeaderLength = 0;

    if (!m_fileDump)
    {
        std::string locale = GetLocale();
        tm* date = localtime(&rawTime);
        // basic file name format:
        char fileName[MAX_PATH];
        // removes the DLL name from the path
        PathRemoveFileSpec(const_cast<char *>(m_dllPath.c_str()));
        // fills the basic file name format
        _snprintf(fileName, MAX_PATH,
            "wowsniff%s%s_%u_%d-%02d-%02d_%02d-%02d-%02d.pkt",
            !locale.empty() ? "_" : "", locale.c_str(), m_build,
            date->tm_year + 1900,
            date->tm_mon + 1,
            date->tm_mday,
            date->tm_hour,
            date->tm_min,
            date->tm_sec);

        // some info
        printf("Sniff dump: %s\n\n", fileName);

        char fullFileName[MAX_PATH];
        _snprintf(fullFileName, MAX_PATH, "%s\\%s", m_dllPath.c_str(), fileName);

        WORD pkt_version    = PKT_VERSION;
        BYTE sniffer_id     = SNIFFER_ID;
        BYTE sessionKey[40] = { 0 };

        m_fileDump = fopen(fullFileName, "wb");
        // PKT 3.1 header
        fwrite("PKT",                           3, 1, m_fileDump);  // magic
        fwrite((WORD*)&pkt_version,             2, 1, m_fileDump);  // major.minor version
        fwrite((BYTE*)&sniffer_id,              1, 1, m_fileDump);  // sniffer id
        fwrite((DWORD*)&m_build,                4, 1, m_fileDump);  // client build
        fwrite(locale.c_str(),                  4, 1, m_fileDump);  // client lang
        fwrite(sessionKey,                     40, 1, m_fileDump);  // session key
        fwrite((DWORD*)&rawTime,                4, 1, m_fileDump);  // started time
        fwrite((DWORD*)&tickCount,              4, 1, m_fileDump);  // started tick's
        fwrite((DWORD*)&optionalHeaderLength,   4, 1, m_fileDump);  // opional header length

        fflush(m_fileDump);
    }

    BYTE* packetData     = info.dataStore->buffer + info.opcodeSize;
    DWORD packetDataSize = info.dataStore->size   - info.opcodeSize;

    fwrite((DWORD*)&info.packetType,            4, 1, m_fileDump);  // direction of the packet
    fwrite((DWORD*)&info.connectionId,          4, 1, m_fileDump);  // connection id
    fwrite((DWORD*)&tickCount,                  4, 1, m_fileDump);  // timestamp of the packet
    fwrite((DWORD*)&optionalHeaderLength,       4, 1, m_fileDump);  // connection id
    fwrite((DWORD*)&info.dataStore->size,       4, 1, m_fileDump);  // size of the packet + opcode lenght
    fwrite((DWORD*)&packetOpcode,               4, 1, m_fileDump);  // opcode

    fwrite(packetData, packetDataSize,          1, m_fileDump);  // data

    printf("%s Size: %u\n", sOpcodeMgr->GetOpcodeNameForLogging(packetOpcode, info.packetType != CMSG).c_str(), packetDataSize);

    fflush(m_fileDump);

    dumpMutex.unlock();
}

Expansions Sniffer::FindExpansion(DWORD build)
{
    // 6.0.2
    if (build >= 19033)
    {
        ADDRESS addr = 0x0;
        HexFindResult res = sHexSearcher->FindOffsets({ '<', 'V', 'e', 'r', 's', 'i', 'o', 'n', '>' }, 0, addr, "Version");
        if (res.Err != ERR_OK)
            return EXPANSION_NONE;

        std::string version = sHexSearcher->ReadString(addr, 11);
        m_expansion = (Expansions)(version.back() - 48);
        return m_expansion;
    }

    // 5.0.4
    if (build >= 16016)
    {
        m_expansion = EXPANSION_MOP;
        return m_expansion;
    }

    // 4.0.1
    if (build >= 13164)
    {
        m_expansion = EXPANSION_CATA;
        return m_expansion;
    }

    // 3.0.2
    if (build >= 9056)
    {
        m_expansion = EXPANSION_WOTLK;
        return m_expansion;
    }

    // 2.0.1
    if (build >= 6180)
    {
        m_expansion = EXPANSION_TBC;
        return m_expansion;
    }

    // 1.1.0
    if (build >= 4044)
    {
        m_expansion = EXPANSION_VANILLA;
        return m_expansion;
    }

    return EXPANSION_NONE;
}
