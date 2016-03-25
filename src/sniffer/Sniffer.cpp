#include "Sniffer.h"
#include "Hooks.h"
#include "OpcodeMgr.h"

std::atomic<bool> Sniffer::m_stopEvent(false);

Sniffer::Sniffer() : m_isTestClient(false) { }

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
    DWORD packetOpcode = 0x0;
    switch (info.opcodeSize)
    {
        case 2: packetOpcode = *(WORD*)info.dataStore->buffer; break;
        case 4: packetOpcode = *(DWORD*)info.dataStore->buffer; break;
        case 6: packetOpcode = *(WORD*)(info.dataStore->buffer + 4); break;
        default: break;
    }

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
    DWORD dataStoreSize  = info.dataStore->size   - info.opcodeSize + 4; // force opcode size 4 for WPP

    fwrite((DWORD*)&info.packetType,            4, 1, m_fileDump);  // direction of the packet
    fwrite((DWORD*)&info.connectionId,          4, 1, m_fileDump);  // connection id
    fwrite((DWORD*)&tickCount,                  4, 1, m_fileDump);  // timestamp of the packet
    fwrite((DWORD*)&optionalHeaderLength,       4, 1, m_fileDump);  // connection id
    fwrite((DWORD*)&dataStoreSize,              4, 1, m_fileDump);  // size of the packet + opcode length
    fwrite((DWORD*)&packetOpcode,               4, 1, m_fileDump);  // opcode

    fwrite(packetData, packetDataSize,          1, m_fileDump);  // data

    printf("%s Size: %u\n", sOpcodeMgr->GetOpcodeNameForLogging(packetOpcode, info.packetType != CMSG).c_str(), packetDataSize);

    fflush(m_fileDump);

    dumpMutex.unlock();
}
