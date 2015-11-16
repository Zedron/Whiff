#ifndef __CLIRUNNABLE_H
#define __CLIRUNNABLE_H

#include "Define.h"
#include "LockedQueue.h"

#define MAX_COMMAND_ARGS 255

struct CliCommandHolder
{
    typedef void Print(void*, const char*);
    typedef void CommandFinished();

    void* m_callbackArg;
    std::string m_command;
    char* m_args[MAX_COMMAND_ARGS];
    Print* m_print;

    CommandFinished* m_commandFinished;

    CliCommandHolder(void* callbackArg, char* command[], Print* zprint, CommandFinished* commandFinished)
        : m_callbackArg(callbackArg), m_print(zprint), m_commandFinished(commandFinished)
    {
        m_command = command[0];

        for (unsigned char i = 1; i < MAX_COMMAND_ARGS; ++i)
            m_args[i - 1] = command[i];
    }

    ~CliCommandHolder() { }

private:
    CliCommandHolder(CliCommandHolder const& right) = delete;
    CliCommandHolder& operator=(CliCommandHolder const& right) = delete;
};

class SnifferConsole
{
public:
    SnifferConsole();
    ~SnifferConsole() { }

    void ProcessCliCommands();
    void QueueCliCommand(CliCommandHolder* commandHolder) { cliCmdQueue.add(commandHolder); }
    void ShutDown();

    void GetConsoleText();
    static void commandFinished();
    static void utf8print(void* /*arg*/, const char* str);

    void SetActive() { m_active = true; }
    void Disable() { m_active = false; }

private:
    std::thread* m_thread;
    LockedQueue<CliCommandHolder*> cliCmdQueue;
    static std::atomic<bool> m_active;
};

#endif