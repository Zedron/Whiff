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

#ifndef _OFFSETSEARCHER_H__
#define _OFFSETSEARCHER_H__

#include "Define.h"

#include "Addresses.h"

using namespace ClientAddresses;

typedef std::set<ADDRESS> Offsets;

enum FindResults
{
    ERR_OK,
    ERR_NOTFOUND,
    ERR_MULTIPLE,
    ERR_ALREADY_EXISTS,
    ERR_MAX,
};

static const char* HexErrorString[ERR_MAX] = {
    "",
    "Offset could not be found",
    "Multiple offsets found",
    "",
};

struct HexFindResult
{
    HexFindResult(FindResults _err, const char* _name = "", bool displayError = true) : Err(_err), Name(_name)
    {
        if (displayError && _err != ERR_OK && _err != ERR_ALREADY_EXISTS)
            printf("Failed to find %s, Error: %s\n", _name, HexErrorString[_err]);
    }
    FindResults Err;
    const char* Name;
};

class HexSearcher
{
public:
    static HexSearcher* instance()
    {
        static HexSearcher instance;
        return &instance;
    }

    Addresses* GetAddresses(Addresses* addresses);

    ADDRESS GetModuleEnd();
    ADDRESS GetModuleBegin();

    Offsets FindOffsets(std::vector<unsigned char> const& pattern, size_t limit = 0);
    HexFindResult FindOffsets(std::vector<unsigned char> const& pattern, size_t limit, ADDRESS& address, const char* func, bool displayError = true);

    std::string ReadString(ADDRESS start, size_t len, bool rebase = true);
    std::string ReadStringR(ADDRESS start, size_t len, bool rebase = true);

private:
    HexSearcher() { }
    ~HexSearcher() { }
};
#define sHexSearcher HexSearcher::instance()

#endif
