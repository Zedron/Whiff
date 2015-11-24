#ifndef _HEXPATTERNS_H__
#define _HEXPATTERNS_H__

#include "Define.h"
#include "Sniffer.h"

namespace HexPatterns
{
    namespace Vanilla
    {
        void Find(Addresses* /*addresses*/)
        {
            if (sSniffer->GetExpansion() != EXPANSION_VANILLA)
                return;
        }
    }

    namespace TBC
    {
        void Find(Addresses* /*addresses*/)
        {
            if (sSniffer->GetExpansion() != EXPANSION_TBC)
                return;
        }
    }

    namespace WotLK
    {
        void Find(Addresses* /*addresses*/)
        {
            if (sSniffer->GetExpansion() != EXPANSION_WOTLK)
                return;
        }
    }

    namespace Cata
    {
        void Find(Addresses* /*addresses*/)
        {
            if (sSniffer->GetExpansion() != EXPANSION_CATA)
                return;
        }
    }

    namespace MoP
    {
        void Find(Addresses* /*addresses*/)
        {
            if (sSniffer->GetExpansion() != EXPANSION_MOP)
                return;
        }
    }

    namespace WoD
    {
        namespace x64
        {
            static const std::vector<unsigned char> NetClient_HandleData() { return { 0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C, 0x24, 0x18, 0x48, 0x89, 0x74, 0x24, 0x20, 0x57, 0x48, 0x83, 0xEC, 0x50, 0x48, 0x8B, 0xD9, 0x48, 0x8B, 0x89, 0x48, 0x06, 0x00, 0x00, 0x49, 0x8B, 0xF9 }; }

            static const std::vector<unsigned char> CDataStore_GetInt32() { return { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xFA, 0x8B, 0x51, 0x1C, 0x41, 0xB8, 0x04, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xD9, 0xE8, 0x00, 0xFE, 0xFF, 0xFF, 0x85, 0xC0 }; }

            static const std::vector<unsigned char> NetClient_Send2() { return { 0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C, 0x24, 0x18, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x20, 0x00, 0x8D, 0x00, 0x38, 0x05, 0x00, 0x00, 0x48, 0x8B, 0xD9 }; }

            static const std::vector<unsigned char> GetCurrentWowLocale() { return { 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x89, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48 }; }

            static const std::vector<unsigned char> GetLocaleNameFromWowEnum() { return { 0x48, 0x63, 0xC1, 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x04, 0xC1, 0xC3, 0xCC, 0x48, 0x63, 0xC1, 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x04, 0x81, 0xC3, 0xCC, 0xCC }; }

            void Find(Addresses* addresses)
            {
                HexFindResult handleData(sHexSearcher->FindOffsets(NetClient_HandleData(), 0, addresses->NetClient_HandleData, "NetClient::HandleData"));
                if (handleData.Err == ERR_OK)
                    printf("Found %s at 0x%X\n", handleData.Name, addresses->NetClient_HandleData);

                HexFindResult send2(sHexSearcher->FindOffsets(NetClient_Send2(), 0, addresses->NetClient_Send2, "NetClient::Send2"));
                if (send2.Err == ERR_OK)
                    printf("Found %s at 0x%X\n", send2.Name, addresses->NetClient_Send2);

                HexFindResult getInt32(sHexSearcher->FindOffsets(CDataStore_GetInt32(), 0, addresses->CDataStore_GetInt32, "CDataStore::GetInt32"));
                if (getInt32.Err == ERR_OK)
                    printf("Found %s at 0x%X\n", getInt32.Name, addresses->CDataStore_GetInt32);

                HexFindResult currentWowLocale(sHexSearcher->FindOffsets(GetCurrentWowLocale(), 0, addresses->GetCurrentWowLocale, "GetCurrentWowLocale"));
                if (currentWowLocale.Err == ERR_OK)
                    printf("Found %s at 0x%X\n", currentWowLocale.Name, addresses->GetCurrentWowLocale);

                HexFindResult localeNameFromWowEnum(sHexSearcher->FindOffsets(GetLocaleNameFromWowEnum(), 0, addresses->GetLocaleNameFromWowEnum, "GetLocaleNameFromWowEnum"));
                if (localeNameFromWowEnum.Err == ERR_OK)
                    printf("Found %s at 0x%X\n", localeNameFromWowEnum.Name, addresses->GetLocaleNameFromWowEnum);
            }
        }

        namespace x86
        {
            static const std::vector<unsigned char> NetClient_ProcessMessage() { return { 0x55, 0x8B, 0xEC, 0xFF, 0x05, 0x00, 0x00, 0x00, 0x00, 0x56, 0x8B }; }

            static const std::vector<unsigned char> NetClient_Send2() { return { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x53, 0x56, 0x8B, 0xF1, 0x8D, 0x8E, 0x34, 0x05 }; }

            static const std::vector<unsigned char> GetCurrentWowLocale() { return { 0xA1, 0x00, 0x00, 0x00, 0x00, 0xC3, 0xA1, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x5D, 0xC3, 0xA1, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x55, 0x8B, 0xEC, 0x56, 0x33, 0xF6, 0x8B, 0x04, 0xB5, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x74, 0x0F }; }

            static const std::vector<unsigned char> GetLocaleNameFromWowEnum() { return { 0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0x8B, 0x04, 0x85, 0x00, 0x00, 0x00, 0x00, 0x5D, 0xC3, 0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0x8B, 0x04, 0x85, 0x00, 0x00, 0x00, 0x00, 0x5D, 0xC3, 0x55, 0x8B }; }

            void Find(Addresses* addresses)
            {
                HexFindResult processMessage(sHexSearcher->FindOffsets(NetClient_ProcessMessage(), 0, addresses->NetClient_ProcessMessage, "NetClient::ProcessMessage"));
                if (processMessage.Err == ERR_OK)
                    printf("Found %s at 0x%X\n", processMessage.Name, addresses->NetClient_ProcessMessage);

                HexFindResult send2(sHexSearcher->FindOffsets(NetClient_Send2(), 0, addresses->NetClient_Send2, "NetClient::Send2"));
                if (send2.Err == ERR_OK)
                    printf("Found %s at 0x%X\n", send2.Name, addresses->NetClient_Send2);

                HexFindResult currentWowLocale(sHexSearcher->FindOffsets(GetCurrentWowLocale(), 0, addresses->GetCurrentWowLocale, "GetCurrentWowLocale"));
                if (currentWowLocale.Err == ERR_OK)
                    printf("Found %s at 0x%X\n", currentWowLocale.Name, addresses->GetCurrentWowLocale);

                HexFindResult localeNameFromWowEnum(sHexSearcher->FindOffsets(GetLocaleNameFromWowEnum(), 0, addresses->GetLocaleNameFromWowEnum, "GetLocaleNameFromWowEnum"));
                if (localeNameFromWowEnum.Err == ERR_OK)
                    printf("Found %s at 0x%X\n", localeNameFromWowEnum.Name, addresses->GetLocaleNameFromWowEnum);
            }
        }

        namespace Test
        {
            namespace x64
            {
                static const std::vector<unsigned char> NetClient_HandleData() { return { 0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x55, 0x57, 0x41, 0x54, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x60, 0x48, 0x8B, 0xD9, 0x48, 0x8B, 0x89, 0x48, 0x06, 0x00, 0x00, 0x49 }; }

                static const std::vector<unsigned char> NetClient_Send2() { return { 0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x6C, 0x24, 0x18, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x48, 0x83, 0xEC, 0x40, 0x48, 0x8B, 0xF9, 0x48, 0x81, 0xC1, 0x38, 0x05 }; }

                static const std::vector<unsigned char> CDataStore_GetInt32() { return { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x40, 0x83, 0x79, 0x1C, 0xFF, 0x48, 0x8B, 0xFA, 0x48, 0x8B, 0xD9, 0x75, 0x40, 0xC7, 0x44, 0x24, 0x38, 0x11, 0x11, 0x11, 0x11, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x01, 0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x01, 0x41, 0xB8, 0xF7, 0x01, 0x00, 0x00, 0xB9, 0x00, 0x00, 0x10, 0x85, 0xC7 }; }

                static const std::vector<unsigned char> GetCurrentWowLocale() { return { 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x89, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x48 }; }

                static const std::vector<unsigned char> GetLocaleNameFromWowEnum() { return { 0x48, 0x63, 0xC1, 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x04, 0xC1, 0xC3, 0xCC, 0x48, 0x63, 0xC1, 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x8B, 0x04, 0x81, 0xC3, 0xCC, 0xCC, 0x48, 0x63, 0xC1, 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x04, 0xC1, 0xC3, 0xCC }; }

                void Find(Addresses* addresses)
                {
                    HexFindResult handleData(sHexSearcher->FindOffsets(NetClient_HandleData(), 0, addresses->NetClient_HandleData, "NetClient::HandleData"));
                    if (handleData.Err == ERR_OK)
                        printf("Found %s at 0x%X\n", handleData.Name, addresses->NetClient_HandleData);

                    HexFindResult send2(sHexSearcher->FindOffsets(NetClient_Send2(), 0, addresses->NetClient_Send2, "NetClient::Send2"));
                    if (send2.Err == ERR_OK)
                        printf("Found %s at 0x%X\n", send2.Name, addresses->NetClient_Send2);

                    HexFindResult getInt32(sHexSearcher->FindOffsets(CDataStore_GetInt32(), 0, addresses->CDataStore_GetInt32, "CDataStore::GetInt32"));
                    if (getInt32.Err == ERR_OK)
                        printf("Found %s at 0x%X\n", getInt32.Name, addresses->CDataStore_GetInt32);

                    HexFindResult currentWowLocale(sHexSearcher->FindOffsets(GetCurrentWowLocale(), 0, addresses->GetCurrentWowLocale, "GetCurrentWowLocale"));
                    if (currentWowLocale.Err == ERR_OK)
                        printf("Found %s at 0x%X\n", currentWowLocale.Name, addresses->GetCurrentWowLocale);

                    HexFindResult localeNameFromWowEnum(sHexSearcher->FindOffsets(GetLocaleNameFromWowEnum(), 0, addresses->GetLocaleNameFromWowEnum, "GetLocaleNameFromWowEnum"));
                    if (localeNameFromWowEnum.Err == ERR_OK)
                        printf("Found %s at 0x%X\n", localeNameFromWowEnum.Name, addresses->GetLocaleNameFromWowEnum);
                }
            }

            namespace x86
            {
                static const std::vector<unsigned char> NetClient_ProcessMessage() { return { 0x55, 0x8B, 0xEC, 0xFF, 0x05, 0x00, 0x00, 0x00, 0x00, 0x53, 0x56, 0x8B, 0x75, 0x10, 0x57, 0x8D }; }

                static const std::vector<unsigned char> NetClient_Send2() { return { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x14, 0x53, 0x56, 0x8B, 0xF1, 0x8D, 0x8E, 0x34, 0x05 }; }

                static const std::vector<unsigned char> GetCurrentWowLocale() { return { 0xA1, 0x00, 0x00, 0x00, 0x00, 0xC3, 0xA1, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0xA3, 0x00, 0x00, 0x00, 0x00, 0x5D, 0xC3, 0xA1, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x55, 0x8B, 0xEC, 0x51, 0x51, 0x83, 0x65, 0xFC, 0x00, 0x53, 0x56, 0x57, 0xBB, 0x11, 0x11, 0x11, 0x11 }; }

                static const std::vector<unsigned char> GetLocaleNameFromWowEnum() { return { 0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0x8B, 0x04, 0x85, 0x00, 0x00, 0x00, 0x00, 0x5D, 0xC3, 0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0x8B, 0x04, 0x85, 0x00, 0x00, 0x00, 0x00, 0x5D, 0xC3, 0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0x8B, 0x04, 0x85, 0x00, 0x00, 0x00, 0x01, 0x5D, 0xC3, 0x55, 0x8B, 0xEC }; }

                void Find(Addresses* addresses)
                {
                    HexFindResult processMessage(sHexSearcher->FindOffsets(NetClient_ProcessMessage(), 0, addresses->NetClient_ProcessMessage, "NetClient::ProcessMessage"));
                    if (processMessage.Err == ERR_OK)
                        printf("Found %s at 0x%X\n", processMessage.Name, addresses->NetClient_ProcessMessage);

                    HexFindResult send2(sHexSearcher->FindOffsets(NetClient_Send2(), 0, addresses->NetClient_Send2, "NetClient::Send2"));
                    if (send2.Err == ERR_OK)
                        printf("Found %s at 0x%X\n", send2.Name, addresses->NetClient_Send2);

                    HexFindResult currentWowLocale(sHexSearcher->FindOffsets(GetCurrentWowLocale(), 0, addresses->GetCurrentWowLocale, "GetCurrentWowLocale"));
                    if (currentWowLocale.Err == ERR_OK)
                        printf("Found %s at 0x%X\n", currentWowLocale.Name, addresses->GetCurrentWowLocale);

                    HexFindResult localeNameFromWowEnum(sHexSearcher->FindOffsets(GetLocaleNameFromWowEnum(), 0, addresses->GetLocaleNameFromWowEnum, "GetLocaleNameFromWowEnum"));
                    if (localeNameFromWowEnum.Err == ERR_OK)
                        printf("Found %s at 0x%X\n", localeNameFromWowEnum.Name, addresses->GetLocaleNameFromWowEnum);
                }
            }

            void Find(Addresses* addresses)
            {
                if (Program::Is64Bit())
                    x64::Find(addresses);
                else
                    x86::Find(addresses);
            }
        }

        void Find(Addresses* addresses)
        {
            if (sSniffer->GetExpansion() != EXPANSION_WOD)
                return;

            if (sSniffer->IsTestClient())
            {
                Test::Find(addresses);
                return;
            }

            if (Program::Is64Bit())
                x64::Find(addresses);
            else
                x86::Find(addresses);
        }

    }

    namespace Legion
    {
        namespace x64
        {
            static const std::vector<unsigned char> NetClient_HandleData() { return {  }; }

            static const std::vector<unsigned char> CDataStore_GetInt32() { return {  }; }

            static const std::vector<unsigned char> NetClient_Send2() { return {  }; }

            static const std::vector<unsigned char> GetCurrentWowLocale() { return {  }; }

            static const std::vector<unsigned char> GetLocaleNameFromWowEnum() { return {  }; }

            void Find(Addresses* addresses)
            {
                HexFindResult handleData(sHexSearcher->FindOffsets(NetClient_HandleData(), 0, addresses->NetClient_HandleData, "NetClient::HandleData"));
                if (handleData.Err == ERR_OK)
                    printf("Found %s at 0x%X\n", handleData.Name, addresses->NetClient_HandleData);

                HexFindResult send2(sHexSearcher->FindOffsets(NetClient_Send2(), 0, addresses->NetClient_Send2, "NetClient::Send2"));
                if (send2.Err == ERR_OK)
                    printf("Found %s at 0x%X\n", send2.Name, addresses->NetClient_Send2);

                HexFindResult getInt32(sHexSearcher->FindOffsets(CDataStore_GetInt32(), 0, addresses->CDataStore_GetInt32, "CDataStore::GetInt32"));
                if (getInt32.Err == ERR_OK)
                    printf("Found %s at 0x%X\n", getInt32.Name, addresses->CDataStore_GetInt32);

                HexFindResult currentWowLocale(sHexSearcher->FindOffsets(GetCurrentWowLocale(), 0, addresses->GetCurrentWowLocale, "GetCurrentWowLocale"));
                if (currentWowLocale.Err == ERR_OK)
                    printf("Found %s at 0x%X\n", currentWowLocale.Name, addresses->GetCurrentWowLocale);

                HexFindResult localeNameFromWowEnum(sHexSearcher->FindOffsets(GetLocaleNameFromWowEnum(), 0, addresses->GetLocaleNameFromWowEnum, "GetLocaleNameFromWowEnum"));
                if (localeNameFromWowEnum.Err == ERR_OK)
                    printf("Found %s at 0x%X\n", localeNameFromWowEnum.Name, addresses->GetLocaleNameFromWowEnum);
            }
        }

        namespace x86
        {
            static const std::vector<unsigned char> NetClient_ProcessMessage() { return {  }; }

            static const std::vector<unsigned char> NetClient_Send2() { return {  }; }

            static const std::vector<unsigned char> GetCurrentWowLocale() { return {  }; }

            static const std::vector<unsigned char> GetLocaleNameFromWowEnum() { return {  }; }

            void Find(Addresses* addresses)
            {
                HexFindResult processMessage(sHexSearcher->FindOffsets(NetClient_ProcessMessage(), 0, addresses->NetClient_ProcessMessage, "NetClient::ProcessMessage"));
                if (processMessage.Err == ERR_OK)
                    printf("Found %s at 0x%X\n", processMessage.Name, addresses->NetClient_ProcessMessage);

                HexFindResult send2(sHexSearcher->FindOffsets(NetClient_Send2(), 0, addresses->NetClient_Send2, "NetClient::Send2"));
                if (send2.Err == ERR_OK)
                    printf("Found %s at 0x%X\n", send2.Name, addresses->NetClient_Send2);

                HexFindResult currentWowLocale(sHexSearcher->FindOffsets(GetCurrentWowLocale(), 0, addresses->GetCurrentWowLocale, "GetCurrentWowLocale"));
                if (currentWowLocale.Err == ERR_OK)
                    printf("Found %s at 0x%X\n", currentWowLocale.Name, addresses->GetCurrentWowLocale);

                HexFindResult localeNameFromWowEnum(sHexSearcher->FindOffsets(GetLocaleNameFromWowEnum(), 0, addresses->GetLocaleNameFromWowEnum, "GetLocaleNameFromWowEnum"));
                if (localeNameFromWowEnum.Err == ERR_OK)
                    printf("Found %s at 0x%X\n", localeNameFromWowEnum.Name, addresses->GetLocaleNameFromWowEnum);
            }
        }

        namespace Test
        {
            namespace x64
            {
                static const std::vector<unsigned char> NetClient_HandleData() { return { 0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x55, 0x57, 0x41, 0x56, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x60, 0x48, 0x8B, 0xD9 }; }

                static const std::vector<unsigned char> NetClient_Send2() { return { 0x48, 0x89, 0x5C, 0x24, 0x10, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x40, 0x48, 0x8B, 0xF9, 0x48 }; }

                static const std::vector<unsigned char> CDataStore_GetInt32() { return { 0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x40, 0x83, 0x79, 0x1C, 0xFF, 0x48, 0x8B, 0xFA, 0x48, 0x8B, 0xD9, 0x75, 0x40, 0xC7, 0x44, 0x24, 0x38, 0x11, 0x11, 0x11, 0x11, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x0D, 0x00, 0x00, 0xFF, 0x00, 0x48, 0x8D, 0x15, 0x00, 0x00, 0xFF, 0x00, 0x41, 0xB8, 0xF8, 0x01, 0x00, 0x00, 0xB9, 0x00, 0x00, 0x10, 0x85, 0xC7 }; }

                static const std::vector<unsigned char> GetCurrentWowLocale() { return { 0x8B, 0x05, 0x00, 0x00, 0x49, 0x00, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0x63, 0xC1, 0x48, 0x8D, 0x0D, 0x56, 0x00 }; }

                static const std::vector<unsigned char> GetLocaleNameFromWowEnum() { return { 0x48, 0x63, 0xC1, 0x48, 0x8D, 0x0D, 0xF6, 0x00, 0xD7, 0x00, 0x48, 0x8B, 0x04, 0xC1, 0xC3, 0xCC }; }

                void Find(Addresses* addresses)
                {
                    HexFindResult handleData(sHexSearcher->FindOffsets(NetClient_HandleData(), 0, addresses->NetClient_HandleData, "NetClient::HandleData"));
                    if (handleData.Err == ERR_OK)
                        printf("Found %s at 0x%X\n", handleData.Name, addresses->NetClient_HandleData);

                    HexFindResult send2(sHexSearcher->FindOffsets(NetClient_Send2(), 0, addresses->NetClient_Send2, "NetClient::Send2"));
                    if (send2.Err == ERR_OK)
                        printf("Found %s at 0x%X\n", send2.Name, addresses->NetClient_Send2);

                    HexFindResult getInt32(sHexSearcher->FindOffsets(CDataStore_GetInt32(), 0, addresses->CDataStore_GetInt32, "CDataStore::GetInt32"));
                    if (getInt32.Err == ERR_OK)
                        printf("Found %s at 0x%X\n", getInt32.Name, addresses->CDataStore_GetInt32);

                    HexFindResult currentWowLocale(sHexSearcher->FindOffsets(GetCurrentWowLocale(), 0, addresses->GetCurrentWowLocale, "GetCurrentWowLocale"));
                    if (currentWowLocale.Err == ERR_OK)
                        printf("Found %s at 0x%X\n", currentWowLocale.Name, addresses->GetCurrentWowLocale);

                    HexFindResult localeNameFromWowEnum(sHexSearcher->FindOffsets(GetLocaleNameFromWowEnum(), 0, addresses->GetLocaleNameFromWowEnum, "GetLocaleNameFromWowEnum"));
                    if (localeNameFromWowEnum.Err == ERR_OK)
                        printf("Found %s at 0x%X\n", localeNameFromWowEnum.Name, addresses->GetLocaleNameFromWowEnum);
                }
            }

            namespace x86
            {
                static const std::vector<unsigned char> NetClient_ProcessMessage() { return { 0x55, 0x8B, 0xEC, 0x51, 0xFF, 0x05, 0xBC, 0x00, 0x00, 0x00, 0x8D, 0x45, 0xFC, 0x53, 0x56, 0x57 }; }

                static const std::vector<unsigned char> NetClient_Send2() { return { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x0C, 0x53, 0x56, 0x57, 0x8B, 0xF9, 0x8D, 0x87, 0x34, 0x05, 0x00 }; }

                static const std::vector<unsigned char> GetCurrentWowLocale() { return { 0xA1, 0x9C, 0x00, 0x00, 0x00, 0xC3, 0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0x8B, 0x04, 0x85, 0x00 }; }

                static const std::vector<unsigned char> GetLocaleNameFromWowEnum() { return { 0x55, 0x8B, 0xEC, 0x8B, 0x45, 0x08, 0x8B, 0x04, 0x85, 0x00, 0x00, 0x00, 0x00, 0x5D, 0xC3, 0x55, 0x8B, 0xEC, 0x8B, 0x55, 0x08, 0x85, 0xD2, 0x74 }; }

                void Find(Addresses* addresses)
                {
                    HexFindResult processMessage(sHexSearcher->FindOffsets(NetClient_ProcessMessage(), 0, addresses->NetClient_ProcessMessage, "NetClient::ProcessMessage"));
                    if (processMessage.Err == ERR_OK)
                        printf("Found %s at 0x%X\n", processMessage.Name, addresses->NetClient_ProcessMessage);

                    HexFindResult send2(sHexSearcher->FindOffsets(NetClient_Send2(), 0, addresses->NetClient_Send2, "NetClient::Send2"));
                    if (send2.Err == ERR_OK)
                        printf("Found %s at 0x%X\n", send2.Name, addresses->NetClient_Send2);

                    HexFindResult currentWowLocale(sHexSearcher->FindOffsets(GetCurrentWowLocale(), 0, addresses->GetCurrentWowLocale, "GetCurrentWowLocale"));
                    if (currentWowLocale.Err == ERR_OK)
                        printf("Found %s at 0x%X\n", currentWowLocale.Name, addresses->GetCurrentWowLocale);

                    HexFindResult localeNameFromWowEnum(sHexSearcher->FindOffsets(GetLocaleNameFromWowEnum(), 0, addresses->GetLocaleNameFromWowEnum, "GetLocaleNameFromWowEnum"));
                    if (localeNameFromWowEnum.Err == ERR_OK)
                        printf("Found %s at 0x%X\n", localeNameFromWowEnum.Name, addresses->GetLocaleNameFromWowEnum);
                }
            }

            void Find(Addresses* addresses)
            {
                if (Program::Is64Bit())
                    x64::Find(addresses);
                else
                    x86::Find(addresses);
            }
        }

        void Find(Addresses* addresses)
        {
            if (sSniffer->GetExpansion() != EXPANSION_LEGION)
                return;

            if (sSniffer->IsTestClient())
            {
                Test::Find(addresses);
                return;
            }

            if (Program::Is64Bit())
                x64::Find(addresses);
            else
                x86::Find(addresses);
        }
    }

    //57 6F 57 20 5B
    static const std::vector<unsigned char> BuildInfo() { return { 'W', 'o', 'W', ' ', '[' }; }

    void FindBuildInfo(Addresses* addresses)
    {
        HexFindResult buildInfo(sHexSearcher->FindOffsets(BuildInfo(), 1, addresses->BuildInfo, "BuildInfo"));
        if (buildInfo.Err == ERR_OK)
            printf("Found %s at 0x%X\n", buildInfo.Name, addresses->BuildInfo);
    }

    void Find(Addresses* addresses)
    {
        switch (sSniffer->GetExpansion())
        {
            case EXPANSION_VANILLA: Vanilla::Find(addresses); break;
            case EXPANSION_TBC:         TBC::Find(addresses); break;
            case EXPANSION_WOTLK:     WotLK::Find(addresses); break;
            case EXPANSION_CATA:       Cata::Find(addresses); break;
            case EXPANSION_MOP:         MoP::Find(addresses); break;
            case EXPANSION_WOD:         WoD::Find(addresses); break;
            case EXPANSION_LEGION:   Legion::Find(addresses); break;
            default:break;
        }
    }
}

#endif
