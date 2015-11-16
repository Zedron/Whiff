#include "SnifferConsole.h"
#include "Util.h"
#include "Sniffer.h"
#include "CommandMgr.h"

std::atomic<bool> SnifferConsole::m_active(false);

SnifferConsole::SnifferConsole()
{
    m_thread = new std::thread(&SnifferConsole::GetConsoleText, this);
}

void SnifferConsole::utf8print(void* /*arg*/, const char* str)
{
    wchar_t wtemp_buf[6000];
    size_t wtemp_len = 6000-1;
    if (!Utf8toWStr(str, strlen(str), wtemp_buf, wtemp_len))
        return;

    char temp_buf[6000];
    CharToOemBuffW(&wtemp_buf[0], &temp_buf[0], (DWORD)wtemp_len+1);
    printf(temp_buf);
}

void SnifferConsole::commandFinished()
{
    if (m_active)
        printf("> ");

    fflush(stdout);
}

void SnifferConsole::GetConsoleText()
{
    // wait for everything to be ready
    while (!Sniffer::IsStopped() && !m_active) { std::this_thread::sleep_for(std::chrono::milliseconds(100)); }

    printf("> ");
    fflush(stdout);

    while (!Sniffer::IsStopped())
    {
        while (!Sniffer::IsStopped() && !m_active) { std::this_thread::sleep_for(std::chrono::milliseconds(100)); }

        char commandbuf[256];
        char *command_str = fgets(commandbuf, sizeof(commandbuf), stdin);

        if (command_str != NULL)
        {
            for (int x = 0; command_str[x]; ++x)
                if (command_str[x] == '\r' || command_str[x] == '\n')
                {
                    command_str[x] = 0;
                    break;
                }

            if (!*command_str)
            {
                printf("> ");
                continue;
            }

            char* command[MAX_COMMAND_ARGS] = { 0 };
            char* arg = NULL;
            int numargs = 0;
            arg = strtok(command_str, " ");

            while (arg != NULL)
            {
                command[numargs] = arg;
                arg = strtok(NULL, " ,.-");
                ++numargs;
            }

            if (!numargs)
                command[0] = command_str;

            fflush(stdout);
            QueueCliCommand(new CliCommandHolder(NULL, command, &utf8print, &commandFinished));
        }
        else if (feof(stdin))
        {
            Sniffer::Stop();
        }
    }
}

void SnifferConsole::ProcessCliCommands()
{
    CliCommandHolder::Print* zprint = NULL;
    void* callbackArg = NULL;
    CliCommandHolder* command = NULL;
    while (cliCmdQueue.next(command))
    {
        zprint = command->m_print;
        callbackArg = command->m_callbackArg;

        if (!sCommandMgr->HandleCommand(command->m_command, command->m_args))
            printf("Invalid command. Type 'help' for a list of commands\n");

        if (command->m_commandFinished)
            command->m_commandFinished();
        delete command;
    }
}

void SnifferConsole::ShutDown()
{
    if (m_thread != nullptr)
    {
        // First try to cancel any I/O in the CLI thread
        if (!CancelSynchronousIo(m_thread->native_handle()))
        {
            // if CancelSynchronousIo() fails, print the error and try with old way
            DWORD errorCode = GetLastError();
            LPSTR errorBuffer;

            DWORD formatReturnCode = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
                                                   nullptr, errorCode, 0, (LPTSTR)&errorBuffer, 0, nullptr);
            if (!formatReturnCode)
                errorBuffer = "Unknown error";

            LocalFree(errorBuffer);

            // send keyboard input to safely unblock the CLI thread
            INPUT_RECORD b[4];
            HANDLE hStdIn = GetStdHandle(STD_INPUT_HANDLE);
            b[0].EventType = KEY_EVENT;
            b[0].Event.KeyEvent.bKeyDown = TRUE;
            b[0].Event.KeyEvent.uChar.AsciiChar = 'X';
            b[0].Event.KeyEvent.wVirtualKeyCode = 'X';
            b[0].Event.KeyEvent.wRepeatCount = 1;

            b[1].EventType = KEY_EVENT;
            b[1].Event.KeyEvent.bKeyDown = FALSE;
            b[1].Event.KeyEvent.uChar.AsciiChar = 'X';
            b[1].Event.KeyEvent.wVirtualKeyCode = 'X';
            b[1].Event.KeyEvent.wRepeatCount = 1;

            b[2].EventType = KEY_EVENT;
            b[2].Event.KeyEvent.bKeyDown = TRUE;
            b[2].Event.KeyEvent.dwControlKeyState = 0;
            b[2].Event.KeyEvent.uChar.AsciiChar = '\r';
            b[2].Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
            b[2].Event.KeyEvent.wRepeatCount = 1;
            b[2].Event.KeyEvent.wVirtualScanCode = 0x1c;

            b[3].EventType = KEY_EVENT;
            b[3].Event.KeyEvent.bKeyDown = FALSE;
            b[3].Event.KeyEvent.dwControlKeyState = 0;
            b[3].Event.KeyEvent.uChar.AsciiChar = '\r';
            b[3].Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
            b[3].Event.KeyEvent.wVirtualScanCode = 0x1c;
            b[3].Event.KeyEvent.wRepeatCount = 1;
            DWORD numb;
            WriteConsoleInput(hStdIn, b, 4, &numb);
        }

        m_thread->join();
        delete m_thread;
    }
}
