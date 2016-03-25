#ifndef _ADDRESSES_H__
#define _ADDRESSES_H__

#include "Define.h"
#include "Util.h"

#include <unordered_map>

namespace ClientAddresses
{
    class Addresses
    {
    public:
        Addresses(ADDRESS _Send2 = 0x0, ADDRESS _ProcMessage = 0x0, ADDRESS _Locale = 0x0, ADDRESS _buildInfo = 0x0,
              ADDRESS oneMessageReady = 0x0, ADDRESS _CDGetInt32 = 0x0, ADDRESS _handleData = 0x0,
              ADDRESS _getCurrentWoWLocale = 0x0, ADDRESS _getLocaleFromEnum = 0x0, ADDRESS _CDGetInt16 = 0x0) :
            NetClient_Send2(_Send2),
            NetClient_ProcessMessage(_ProcMessage),
            Locale(_Locale),
            BuildInfo(_buildInfo),
            NetClient_OneMessageReady(oneMessageReady),
            CDataStore_GetInt32(_CDGetInt32),
            NetClient_HandleData(_handleData),
            GetCurrentWowLocale(_getCurrentWoWLocale),
            GetLocaleNameFromWowEnum(_getLocaleFromEnum),
            CDataStore_GetInt16(_CDGetInt16)
        { }

        ADDRESS NetClient_Send2;
        ADDRESS NetClient_ProcessMessage; // x86
        ADDRESS Locale;
        ADDRESS BuildInfo;
        ADDRESS NetClient_OneMessageReady; // WoD x64 Not Used
        ADDRESS CDataStore_GetInt32;       // WoD x64
        ADDRESS NetClient_HandleData;      // WoD x64
        ADDRESS GetCurrentWowLocale;
        ADDRESS GetLocaleNameFromWowEnum;
        ADDRESS CDataStore_GetInt16;       // WoD x64 (post 20886)

        bool IsValid() { return NetClient_Send2 && (NetClient_ProcessMessage || (CDataStore_GetInt32 && NetClient_HandleData)); }
    };

    static std::unordered_map<DWORD, Addresses*> FunctionAddresses;

    static void InitAddresses32()
    {
        #ifndef _WIN64
        FunctionAddresses[5875]  = new Addresses(0x5B5630, 0x537AA0);
        FunctionAddresses[8606]  = new Addresses(0x4203B0, 0x55F440);
        FunctionAddresses[12340] = new Addresses(0x4675F0, 0x631FE0);
        FunctionAddresses[13623] = new Addresses(0x55EF20, 0x490360);
        FunctionAddresses[15595] = new Addresses(0x489590, 0x4873D0);
        FunctionAddresses[16135] = new Addresses(0x7F9AE0, 0x7F7710);
        FunctionAddresses[16357] = new Addresses(0x80C5D0, 0x80A210);
        FunctionAddresses[16650] = new Addresses(0x848D10, 0x846720);
        FunctionAddresses[16709] = new Addresses(0x848FB0, 0x846A00);
        FunctionAddresses[16826] = new Addresses(0x848E40, 0x846880);
        FunctionAddresses[16981] = new Addresses(0x763B57, 0x761C6D);
        FunctionAddresses[16983] = new Addresses(0x76400D, 0x762123);
        FunctionAddresses[16992] = new Addresses(0x76424A, 0x762360);
        FunctionAddresses[17055] = new Addresses(0x763F76, 0x76206E);
        FunctionAddresses[17056] = new Addresses(0x7E43D9, 0x7E1ECC);
        FunctionAddresses[17093] = new Addresses(0x7EED60, 0x7EC853);
        FunctionAddresses[17116] = new Addresses(0x764654, 0x76276A);
        FunctionAddresses[17124] = new Addresses(0x7F3B0F, 0x7F1490);
        FunctionAddresses[17128] = new Addresses(0x763C88, 0x761D9B);
        FunctionAddresses[17359] = new Addresses(0x791942, 0x78F9C5);
        FunctionAddresses[17371] = new Addresses(0x79192A, 0x78F9AD);
        FunctionAddresses[17399] = new Addresses(0x79199E, 0x78FA21);
        FunctionAddresses[17538] = new Addresses(0x78F1A9, 0x78D225);
        FunctionAddresses[17658] = new Addresses(0x7988D7, 0x7965BB, 0x127080C);
        FunctionAddresses[17688] = new Addresses(0x7988D7, 0x7965BB, 0x127080C);
        FunctionAddresses[17898] = new Addresses(0x799B6A, 0x7979B2, 0x1273344);
        FunctionAddresses[17930] = new Addresses(0x79A93E, 0x798786, 0x1275344);
        FunctionAddresses[17956] = new Addresses(0x79A66A, 0x798482, 0x1275344);
        FunctionAddresses[18019] = new Addresses(0x79A8E3, 0x7986FB, 0x1275344);
        FunctionAddresses[18291] = new Addresses(0x799DCD, 0x797CC3, 0x127582C);
        FunctionAddresses[18414] = new Addresses(0x799DF8, 0x797CEE, 0x127582C);
        FunctionAddresses[19033] = new Addresses(0x6539ED, 0x651C5D, 0x1284404);
        FunctionAddresses[19034] = new Addresses(0x6537A5, 0x651C0D, 0x1284404);
        FunctionAddresses[19103] = new Addresses(0x654D40, 0x6531A5, 0x128566C);
        FunctionAddresses[19116] = new Addresses(0x655171, 0x6535D6, 0x12867AC);
        FunctionAddresses[19243] = new Addresses(0x654FC8, 0x65342D, 0x12867AC);
        FunctionAddresses[19342] = new Addresses(0x6556F0, 0x653B55, 0x12867AC);
        FunctionAddresses[19678] = new Addresses(0x664162, 0x6625C2, 0x132382C);
        #endif
    }

    static void InitAddresses64()
    {
        #ifdef _WIN64
        #endif
    }

    static void InitAddresses()
    {
        if (Program::Is64Bit())
            InitAddresses64();
        else
            InitAddresses32();
    }

    static void FreeAddresses()
    {
        while (!FunctionAddresses.empty())
        {
            Addresses* addresses = FunctionAddresses.begin()->second;
            delete addresses;
            FunctionAddresses.erase(FunctionAddresses.begin());
        }
    }

    static Addresses* GetFuncAddresses(DWORD build)
    {
        if (FunctionAddresses.find(build) == FunctionAddresses.end())
            return nullptr;

        return FunctionAddresses[build];;
    }

};

#endif
