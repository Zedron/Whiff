#ifndef _CommandHandler_h__
#define _CommandHandler_h__

#include <unordered_map>

#include "CommandMgr.h"

typedef bool(CommandMgr::*pCommandHandler)(char** command);

struct CommandHandler
{
    CommandHandler() {}
    CommandHandler(const std::string& _name, const char* _help, pCommandHandler _handler)
        : Handler(_handler), Name(_name), Help(_help) {}

    pCommandHandler Handler;
    const std::string Name;
    const char* Help;
};

typedef std::unordered_map<std::string, CommandHandler*> Commands;
extern Commands commandTable;

inline CommandHandler* GetCommandHandler(const std::string& command)
{
    Commands::const_iterator itr = commandTable.find(command);
    if (itr != commandTable.end())
        return itr->second;

    return nullptr;
}

#endif
