#ifndef _HOOKS_H__
#define _HOOKS_H__

#include "DetourManager.h"
#include "HexSearcher.h"

namespace Trampolines
{
    std::mutex recvmtx;
    std::mutex sendmtx;

    namespace Vanilla
    {
        int __fastcall NetClient_ProcessMessage(void* thisPTR, void* dummy, void* param1, CDataStore* dataStore)
        {
            recvmtx.lock();
            PacketInfo packetInfo(SMSG, 0, 2, dataStore);
            sSniffer->DumpPacket(packetInfo);
            int retCode = sDetourMgr->GetDetour<decltype(&NetClient_ProcessMessage)>(HOOK_PROCESSMESSAGE)->GetOriginalFunction()(thisPTR, dummy, param1, dataStore);
            recvmtx.unlock();
            return retCode;
        }

        int __fastcall NetClient_Send2(void* thisPTR, void* dummy, CDataStore* dataStore, int connectionId)
        {
            sendmtx.lock();
            PacketInfo packetInfo(CMSG, connectionId, 4, dataStore);
            sSniffer->DumpPacket(packetInfo);
            int retCode = sDetourMgr->GetDetour<decltype(&NetClient_Send2)>(HOOK_SEND2)->GetOriginalFunction()(thisPTR, dummy, dataStore, connectionId);
            sendmtx.unlock();
            return retCode;
        }

        bool InitProcessMessage()
        {
            ClientAddresses::Addresses const* addresses = sSniffer->GetAddresses();
            return sDetourMgr->CreateDetour<decltype(&NetClient_ProcessMessage)>(HOOK_PROCESSMESSAGE, addresses->NetClient_ProcessMessage, &NetClient_ProcessMessage);
        }

        bool InitSend2()
        {
            ClientAddresses::Addresses const* addresses = sSniffer->GetAddresses();
            return sDetourMgr->CreateDetour<decltype(&NetClient_Send2)>(HOOK_SEND2, addresses->NetClient_Send2, &NetClient_Send2);
        }

        std::string GetLocale()
        {
            return sHexSearcher->ReadStringR(sSniffer->GetAddresses()->Locale, 4);
        }

        bool Init()
        {
            ASSERT(GetExpansion(sSniffer->GetBuild()) == EXPANSION_VANILLA);

            if (!InitProcessMessage())
                return false;

            if (!InitSend2())
                return false;

            return true;
        }
    }

    namespace TBC
    {
        bool InitProcessMessage() { return Vanilla::InitProcessMessage(); }
        bool InitSend2()          { return Vanilla::InitSend2(); }

        std::string GetLocale() { return Vanilla::GetLocale(); }

        bool Init()
        {
            ASSERT(GetExpansion(sSniffer->GetBuild()) == EXPANSION_TBC);

            if (!InitProcessMessage())
                return false;

            if (!InitSend2())
                return false;

            return true;
        }
    }

    namespace WotLK
    {
        int __fastcall NetClient_ProcessMessage(void* thisPTR, void* dummy, void* param1, CDataStore* dataStore, void* connectionId)
        {
            recvmtx.lock();
            PacketInfo packetInfo(SMSG, (int)connectionId, 2, dataStore);
            sSniffer->DumpPacket(packetInfo);
            int retCode = sDetourMgr->GetDetour<decltype(&NetClient_ProcessMessage)>(HOOK_PROCESSMESSAGE)->GetOriginalFunction()(thisPTR, dummy, param1, dataStore, connectionId);
            recvmtx.unlock();
            return retCode;
        }

        bool InitProcessMessage()
        {
            ClientAddresses::Addresses const* addresses = sSniffer->GetAddresses();
            return sDetourMgr->CreateDetour<decltype(&NetClient_ProcessMessage)>(HOOK_PROCESSMESSAGE, addresses->NetClient_ProcessMessage, &NetClient_ProcessMessage);
        }

        bool InitSend2() { return Vanilla::InitSend2(); }

        std::string GetLocale() { return Vanilla::GetLocale(); }

        bool Init()
        {
            ASSERT(GetExpansion(sSniffer->GetBuild()) == EXPANSION_WOTLK);

            if (!InitProcessMessage())
                return false;

            if (!InitSend2())
                return false;

            return true;
        }
    }

    namespace Cata
    {
        bool InitProcessMessage() { return WotLK::InitProcessMessage(); }
        bool InitSend2()          { return Vanilla::InitSend2(); }

        std::string GetLocale() { return Vanilla::GetLocale(); }

        bool Init()
        {
            ASSERT(GetExpansion(sSniffer->GetBuild()) == EXPANSION_CATA);

            if (!InitProcessMessage())
                return false;

            if (!InitSend2())
                return false;

            return true;
        }
    }

    namespace MoP
    {
        int __fastcall NetClient_ProcessMessage(void* thisPTR, void* dummy, void* param1, CDataStore* dataStore, void* connectionId)
        {
            recvmtx.lock();
            PacketInfo packetInfo(SMSG, (int)connectionId, 4, dataStore);
            sSniffer->DumpPacket(packetInfo);
            int retCode = sDetourMgr->GetDetour<decltype(&NetClient_ProcessMessage)>(HOOK_PROCESSMESSAGE)->GetOriginalFunction()(thisPTR, dummy, param1, dataStore, connectionId);
            recvmtx.unlock();
            return retCode;
        }

        bool InitProcessMessage()
        {
            ClientAddresses::Addresses const* addresses = sSniffer->GetAddresses();
            return sDetourMgr->CreateDetour<decltype(&NetClient_ProcessMessage)>(HOOK_PROCESSMESSAGE, addresses->NetClient_ProcessMessage, &NetClient_ProcessMessage);
        }

        bool InitSend2()          { return Vanilla::InitSend2(); }

        std::string GetLocale() { return Vanilla::GetLocale(); }

        bool Init()
        {
            ASSERT(GetExpansion(sSniffer->GetBuild()) == EXPANSION_MOP);

            if (!InitProcessMessage())
                return false;

            if (!InitSend2())
                return false;

            return true;
        }
    }

    namespace WoD
    {
        namespace x86
        {
            int __fastcall NetClient_ProcessMessage(void* thisPTR, void* dummy, void* param1, void* param2, CDataStore* dataStore, void* connectionId)
            {
                recvmtx.lock();
                PacketInfo packetInfo(SMSG, (int)connectionId, 4, dataStore);
                sSniffer->DumpPacket(packetInfo);
                int retCode = sDetourMgr->GetDetour<decltype(&NetClient_ProcessMessage)>(HOOK_PROCESSMESSAGE)->GetOriginalFunction()(thisPTR, dummy, param1, param2, dataStore, connectionId);
                recvmtx.unlock();
                return retCode;
            }

            typedef int(*GetCurrentWowLocaleFn)(void);
            int GetWoWLocaleEnum()
            {
                ClientAddresses::Addresses const* addresses = sSniffer->GetAddresses();
                if (!addresses->GetCurrentWowLocale)
                    return 0;

                return GetCurrentWowLocaleFn(EXE_REBASE(addresses->GetCurrentWowLocale))();
            }

            typedef char*(__cdecl *GetLocaleNameFromWowEnumFn)(int);
            std::string GetLocale()
            {
                ClientAddresses::Addresses const* addresses = sSniffer->GetAddresses();
                if (addresses->Locale)
                    return sHexSearcher->ReadStringR(addresses->Locale, 4);

                if (!addresses->GetLocaleNameFromWowEnum)
                    return nullptr;

                return std::string(GetLocaleNameFromWowEnumFn(EXE_REBASE(addresses->GetLocaleNameFromWowEnum))(GetWoWLocaleEnum()));
            }

            bool InitProcessMessage()
            {
                ClientAddresses::Addresses const* addresses = sSniffer->GetAddresses();
                if (!sDetourMgr->CreateDetour<decltype(&NetClient_ProcessMessage)>(HOOK_PROCESSMESSAGE, addresses->NetClient_ProcessMessage, &NetClient_ProcessMessage))
                    return false;

                return true;
            }

            bool InitSend2() { return Vanilla::InitSend2(); }

            bool Init()
            {
                if (!InitProcessMessage())
                    return false;

                if (!InitSend2())
                    return false;

                return true;
            }
        }

        namespace x64
        {
            void __fastcall NetClient_Send2(void* thisPTR, CDataStore* dataStore, int connectionId)
            {
                sendmtx.lock();
                PacketInfo packetInfo(CMSG, connectionId, 4, dataStore);
                sSniffer->DumpPacket(packetInfo);
                sDetourMgr->GetDetour<decltype(&NetClient_Send2)>(HOOK_SEND2)->GetOriginalFunction()(thisPTR, dataStore, connectionId);
                sendmtx.unlock();
            }

            // NOT USED
            void __fastcall NetClient_OneMessageReady(void* dataStore, void* wowConnection, void* a3, const char* connectionStr)
            {
                sDetourMgr->GetDetour<decltype(&NetClient_OneMessageReady)>(HOOK_MESSAGEREADY)->GetOriginalFunction()(dataStore, wowConnection, a3, connectionStr);
            }

            // Blizz inlined NetClient::ProcessMessage in x64, so we have nothing we can easily hook to
            // my alternative: hook CDataStore::GetInt32, which passes the dataStore we need to dump the packet
            // and only dump the first call that follows NetClient::HandleData
            // this func is also called on multiple threads, so we have to check to make sure we are on the correct thread
            // tldr this is a hack
            std::thread::id recvThreadId;
            __int64 __fastcall CDataStore_GetInt32(CDataStore* dataStore, void* unk)
            {
                __int64 ret = sDetourMgr->GetDetour<decltype(&CDataStore_GetInt32)>(HOOK_CDGETINT32)->GetOriginalFunction()(dataStore, unk);

                if (std::this_thread::get_id() == recvThreadId)
                {
                    PacketInfo packetInfo(SMSG, 0, 4, dataStore);
                    sSniffer->DumpPacket(packetInfo);
                    recvThreadId = std::thread::id();
                }
                return ret;
            }

            __int64 __fastcall NetClient_HandleData(void* a1, void* a2, void* a3, void* a4, int unk)
            {
                recvmtx.lock();

                ASSERT(recvThreadId == std::thread::id());
                recvThreadId = std::this_thread::get_id();
                __int64 ret = sDetourMgr->GetDetour<decltype(&NetClient_HandleData)>(HOOK_HANDLEDATA)->GetOriginalFunction()(a1, a2, a3, a4, unk);

                recvmtx.unlock();
                return ret;
            }

            typedef __int64(*GetCurrentWowLocaleFn)(void);
            int GetWoWLocaleEnum()
            {
                ClientAddresses::Addresses const* addresses = sSniffer->GetAddresses();
                if (!addresses->GetCurrentWowLocale)
                    return 0;

                return (int)GetCurrentWowLocaleFn(EXE_REBASE(addresses->GetCurrentWowLocale))();
            }

            typedef char*(__fastcall *GetLocaleNameFromWowEnumFn)(int);
            std::string GetLocale()
            {
                ClientAddresses::Addresses const* addresses = sSniffer->GetAddresses();
                if (!addresses->GetLocaleNameFromWowEnum || addresses->Locale)
                    return sHexSearcher->ReadStringR(addresses->Locale, 4);

                return std::string(GetLocaleNameFromWowEnumFn(EXE_REBASE(addresses->GetLocaleNameFromWowEnum))(GetWoWLocaleEnum()));
            }

            bool AttachSend2()
            {
                ClientAddresses::Addresses const* addresses = sSniffer->GetAddresses();
                return sDetourMgr->CreateDetour<decltype(&NetClient_Send2)>(HOOK_SEND2, addresses->NetClient_Send2, &NetClient_Send2);
            }

            bool AttachOneMessageReady()
            {
                ClientAddresses::Addresses const* addresses = sSniffer->GetAddresses();
                return sDetourMgr->CreateDetour<decltype(&NetClient_OneMessageReady)>(HOOK_MESSAGEREADY, addresses->NetClient_OneMessageReady, &NetClient_OneMessageReady);
            }

            bool AttachCDGetInt32()
            {
                ClientAddresses::Addresses const* addresses = sSniffer->GetAddresses();
                return sDetourMgr->CreateDetour<decltype(&CDataStore_GetInt32)>(HOOK_CDGETINT32, addresses->CDataStore_GetInt32, &CDataStore_GetInt32);
            }

            bool AttachHandleData()
            {
                recvThreadId = std::thread::id();
                ClientAddresses::Addresses const* addresses = sSniffer->GetAddresses();
                return sDetourMgr->CreateDetour<decltype(&NetClient_HandleData)>(HOOK_HANDLEDATA, addresses->NetClient_HandleData, &NetClient_HandleData);
            }

            bool Init()
            {
                if (!AttachSend2())
                    return false;

                if (!AttachHandleData())
                    return false;

                if (!AttachCDGetInt32())
                    return false;

                return true;
            }
        }

        std::string GetLocale() { return (Program::Is64Bit() ? x64::GetLocale() : x86::GetLocale()); }

        bool Init()
        {
            ASSERT(GetExpansion(sSniffer->GetBuild()) == EXPANSION_WOD);
            return (Program::Is64Bit() ? x64::Init() : x86::Init());
        }
    }

    namespace Legion
    {
        bool Init() { return true; }

        std::string GetLocale() { return std::string(); }
    }

    std::string GetLocale()
    {
        switch (GetExpansion(sSniffer->GetBuild()))
        {
            case EXPANSION_VANILLA: return Vanilla::GetLocale();
            case EXPANSION_TBC:     return     TBC::GetLocale();
            case EXPANSION_WOTLK:   return   WotLK::GetLocale();
            case EXPANSION_CATA:    return    Cata::GetLocale();
            case EXPANSION_MOP:     return     MoP::GetLocale();
            case EXPANSION_WOD:     return     WoD::GetLocale();
            case EXPANSION_LEGION:  return  Legion::GetLocale();
            default:                return std::string();
        }
    }

    bool Init()
    {
        switch (GetExpansion(sSniffer->GetBuild()))
        {
            case EXPANSION_VANILLA: return Vanilla::Init();
            case EXPANSION_TBC:     return     TBC::Init();
            case EXPANSION_WOTLK:   return   WotLK::Init();
            case EXPANSION_CATA:    return    Cata::Init();
            case EXPANSION_MOP:     return     MoP::Init();
            case EXPANSION_WOD:     return     WoD::Init();
            case EXPANSION_LEGION:  return  Legion::Init();
            default:                return false;
        }
    }
}

#endif