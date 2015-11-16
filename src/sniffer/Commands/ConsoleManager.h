
#ifndef _CONSOLEMANAGER_H__
#define _CONSOLEMANAGER_H__

#include "Define.h"
#include "Util.h"

#include <Windows.h>

// manages the console
// console should be accessed, created and destroyed through this class
class ConsoleManager
{
public:
    // creates the console
    static bool Create(volatile bool* sniffingLoopCondition)
    {
        // basically creates the console
        if (!AllocConsole())
            return false;

        // registers a handler which handles SIGINT (CTRL-C) signal
        // basically the handler routine will be called when
        // CTRL-C (exit) will be pressed
        if (!SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleManager::SignalHandler_SIGINT, TRUE))
            return false;

        // just be sure there's a STDOUT and STDIN
        HANDLE standardOutputHandler = GetStdHandle(STD_OUTPUT_HANDLE);
        if (!standardOutputHandler || standardOutputHandler == INVALID_HANDLE_VALUE)
            return false;

        HANDLE standardInputHandler = GetStdHandle(STD_INPUT_HANDLE);
        if (!standardOutputHandler || standardOutputHandler == INVALID_HANDLE_VALUE)
            return false;

        if (Program::Is64Bit())
            SetConsoleTitle("Whiff Console (64 bit)");
        else
            SetConsoleTitle("Whiff Console (32 bit)");

        // re-opens STDOUT and STDIN handle as a console window output
        freopen("CONOUT$", "w", stdout);
        freopen("CONIN$", "r", stdin);

        // "sniffing loop" is only looping when this boolean is true
        // so just set this to false to stop it
        _sniffingLoopCondition = sniffingLoopCondition;

        return true;
    }

    // destroys the console
    static void Destroy() { FreeConsole(); }

    // this method will be called when a CTRL-C event occures
    // should stop the sniffing loop, so the sniffer will be stopped
    static BOOL SignalHandler_SIGINT(DWORD type)
    {
        // SIGINT
        printf("\nQuiting...\n");
        // stops the sniffing loop
        *_sniffingLoopCondition = true;
        return TRUE;
    }

private:
    // pointer to a boolean which is true when sniffing is still in progress
    // and false when sniffing should stop
    static volatile bool* _sniffingLoopCondition;
};

#endif
