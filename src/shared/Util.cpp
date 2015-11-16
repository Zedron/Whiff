#include "Util.h"
#include "Shlwapi.h"

bool Utf8toWStr(char const* utf8str, size_t csize, wchar_t* wstr, size_t& wsize)
{
    try
    {
        size_t len = utf8::distance(utf8str, utf8str+csize);
        if (len > wsize)
        {
            if (wsize > 0)
                wstr[0] = L'\0';
            wsize = 0;
            return false;
        }

        wsize = len;
        utf8::utf8to16(utf8str, utf8str+csize, wstr);
        wstr[len] = L'\0';
    }
    catch(std::exception)
    {
        if (wsize > 0)
            wstr[0] = L'\0';
        wsize = 0;
        return false;
    }

    return true;
}

bool WStrToUtf8(std::wstring const& wstr, std::string& utf8str)
{
    try
    {
        std::string utf8str2;
        utf8str2.resize(wstr.size()*4);                     // allocate for most long case

        if (wstr.size())
        {
            char* oend = utf8::utf16to8(wstr.c_str(), wstr.c_str()+wstr.size(), &utf8str2[0]);
            utf8str2.resize(oend-(&utf8str2[0]));                // remove unused tail
        }
        utf8str = utf8str2;
    }
    catch(std::exception)
    {
        utf8str.clear();
        return false;
    }

    return true;
}

bool consoleToUtf8(const std::string& conStr, std::string& utf8str)
{
    std::wstring wstr;
    wstr.resize(conStr.size());
    OemToCharBuffW(&conStr[0], &wstr[0], (DWORD)conStr.size());

    return WStrToUtf8(wstr, utf8str);
}

namespace Program
{
    void Assert(char const* file, int line, char const* function, char const* message)
    {
        printf("\n%s:%i in %s ASSERTION FAILED:\n  %s\n", file, line, function, message);
        system("pause");
        FreeLibraryAndExitThread((HINSTANCE)GetModuleHandle(NULL), 0);
    }

    void Assert(char const* file, int line, char const* function, char const* message, char const* format, ...)
    {
        va_list args;
        va_start(args, format);

        printf("\n%s:%i in %s ASSERTION FAILED:\n  %s\n", file, line, function, message);
        printf(format, args);
        printf("\n");

        va_end(args);
        system("pause");
        FreeLibraryAndExitThread((HINSTANCE)GetModuleHandle(NULL), 0);
    }
}

// returns the build number of the client
// returns 0 if an error occurred
// (gets this from file version info of client's exe)
//
// param should be NULL when would like to get the
// path of the _current_ process' executable
// this means the sniffer should call this with NULL because
// the sniffer is just a "thread" which running in WoW
//
// param should NOT be NULL when would like to get the
// path of an _external_ process' executable
// so in the injector the param should contain the handle of a WoW process
WORD GetBuildNumberFromProcess(HANDLE hProcess)
{
    // will contain where the process is which will be injected
    char processExePath[MAX_PATH];

    // size of the path
    DWORD processExePathSize = 0;
    // gets the path of the current process' executable
    // param process should be NULL in the sniffer
    if (!hProcess)
        processExePathSize = GetModuleFileNameA(NULL, processExePath, MAX_PATH);
    // gets the path of an external process' executable
    // param process should NOT be NULL in the injector
    else
        processExePathSize = GetModuleFileNameExA(hProcess, NULL, processExePath, MAX_PATH);
    if (!processExePathSize)
    {
        printf("ERROR: Can't get path of the process' exe, ErrorCode: %u\n", GetLastError());
        return 0;
    }
    printf("ExePath: %s\n", processExePath);

    // size of the file version info
    DWORD fileVersionInfoSize = GetFileVersionInfoSize(processExePath, NULL);
    if (!fileVersionInfoSize)
    {
        printf("ERROR: Can't get size of the file version info,");
        printf("ErrorCode: %u\n", GetLastError());
        return 0;
    }

    // allocates memory for file version info
    BYTE* fileVersionInfoBuffer = new BYTE[fileVersionInfoSize];
    // gets the file version info
    if (!GetFileVersionInfo(processExePath, 0, fileVersionInfoSize, fileVersionInfoBuffer))
    {
        printf("ERROR: Can't get file version info, ErrorCode: %u\n", GetLastError());
        delete[] fileVersionInfoBuffer;
        return 0;
    }

    // structure of file version info
    // actually this pointer will be pointed to a part of fileVersionInfoBuffer
    VS_FIXEDFILEINFO* fileInfo = NULL;
    // gets the needed info (root) from the file version info resource
    // \ means the root block (VS_FIXEDFILEINFO)
    // note: escaping needed so that's why \\ used
    if (!VerQueryValueA(fileVersionInfoBuffer, "\\", (LPVOID*)&fileInfo, NULL))
    {
        printf("ERROR: File version info query is failed.\n");
        delete[] fileVersionInfoBuffer;
        return 0;
    }

    // last (low) 2 bytes
    WORD buildNumber = fileInfo->dwFileVersionLS & 0xFFFF;
    delete[] fileVersionInfoBuffer;
    return buildNumber;
}
