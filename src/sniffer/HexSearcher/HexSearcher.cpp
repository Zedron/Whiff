/*
 * Copyright (C) 2012-2014 Arctium Emulation <http://arctium.org>
 * Copyright (C) 2008-2015 TrinityCore <http://www.trinitycore.org/>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "HexSearcher.h"
#include "HexPatterns.h"

Addresses* HexSearcher::GetAddresses(Addresses* addresses)
{
    bool create = false;

    if (!addresses)
    {
        addresses = new Addresses();
        create = true;
    }

    HexPatterns::FindBuildInfo(addresses);
    if (addresses->BuildInfo)
    {
        std::string buildStr(ReadString(addresses->BuildInfo + 5, 40));
        if (buildStr.find("Release Assertions Enabled") != std::string::npos)
            sSniffer->SetTestClient();
        else if (buildStr.find("Release") == std::string::npos)
            printf("WARNING: Build does not appear to be supported.\n");
    }

    HexPatterns::Find(addresses);
    if (!addresses->IsValid())
    {
        if (create)
            delete addresses;

        return nullptr;
    }

    return addresses;
}

ADDRESS HexSearcher::GetModuleEnd()
{
    MODULEINFO mi;
    HMODULE moduleHandle = GetModuleHandle(NULL);
    GetModuleInformation(GetCurrentProcess(), moduleHandle, &mi, sizeof(mi));
    return (ADDRESS)mi.SizeOfImage + (ADDRESS)moduleHandle;
}

ADDRESS HexSearcher::GetModuleBegin()
{
    return (ADDRESS)GetModuleHandle(NULL);
}

// returns rebased addresses
Offsets HexSearcher::FindOffsets(std::vector<unsigned char> const& pattern, size_t limit)
{
    Offsets offsets;
    ADDRESS begin = GetModuleBegin();
    ADDRESS end = GetModuleEnd();

    // loop through every hex value in the binary
    for (ADDRESS i = begin; (i + pattern.size()) < end; ++i)
    {
        if (limit && offsets.size() >= limit)
            break;

        size_t matches = 0;

        for (size_t j = 0; j < pattern.size(); j++)
        {
             // 0x00, any val
            if (pattern[j] == 0)
            {
                matches++;
                continue;
            }

            //ADDRESS static_address = STATIC_REBASE(i + j);

            // pattern doesn't match, retry @ next hex val
            unsigned char ch = *(unsigned char*)(i + j);
            if (ch != pattern[j])
                break;

            matches++;
        }

        if (matches == pattern.size())
        {
            offsets.insert(i);
            i += matches;
        }
    }

    return offsets;
}

HexFindResult HexSearcher::FindOffsets(std::vector<unsigned char> const& pattern, size_t limit, ADDRESS& address, const char* func, bool displayError)
{
    if (address)
        return HexFindResult(ERR_ALREADY_EXISTS, func, displayError);

    Offsets offsets(FindOffsets(pattern, limit));

    if (offsets.empty())
        return HexFindResult(ERR_NOTFOUND, func, displayError);

    if (offsets.size() > 1)
        return HexFindResult(ERR_MULTIPLE, func, displayError);

    address = STATIC_REBASE(*offsets.begin());
    return HexFindResult(ERR_OK, func, displayError);
}

std::string HexSearcher::ReadString(ADDRESS start, size_t len, bool rebase)
{
    std::string str;
    if (!start)
        return str;

    for (size_t i = 0; i < len; ++i)
        str += *(char*)(rebase ? EXE_REBASE(start + i) : (start + i));

    return str;
}

std::string HexSearcher::ReadStringR(ADDRESS start, size_t len, bool rebase)
{
    std::string str;
    if (!start)
        return str;

    for (size_t i = len; i > 0; --i)
        str += *(char*)(rebase ? EXE_REBASE(start + i - 1) : (start + i - 1));

    return str;
}
