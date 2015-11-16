
#include <Windows.h>
#include <TlHelp32.h>
#include <Aclapi.h>
#include <list>
#include "Util.h"
#include <map>
#include <string>
#include "Addresses.h"

#define WOW_PROCESSES 8

struct BasicAppInfo
{
    bool is64;
    std::string processName;
};

static BasicAppInfo WoWProcesses[WOW_PROCESSES] = {
    { true,  "wow-64.exe"          },
    { true,  "wow-64_patched.exe"  },
    { true,  "wowt-64.exe"         },
    { true,  "wowt-64_patched.exe" },
    { false, "wow.exe"             },
    { false, "wow_patched.exe"     },
    { false, "wowt.exe"            },
    { false, "wowt_patched.exe"    },
};

// this DLL will be injected
#if defined(_WIN64)
  const char injectDLLName[] = "Whiff-64.dll";
#else
  const char injectDLLName[] = "Whiff.dll";
#endif

// this module contains function loadDLLFunctionName
const char loadedModuleName[] = "kernel32.dll";
// basically this function loads/injects the DLL
const char loadDLLFunctionName[] = "LoadLibraryA";

// list container which stores PIDs
typedef std::map<DWORD, std::string> PIDMap;

DWORD SelectProcess(const char* processName);
// gets PIDs of the processes which found by name
void GetProcessIDsByName(PIDMap& /*pids*/, const std::string& /* processName */);
// returns true if the specific process already injeted with the specific DLL
bool IsProcessAlreadyInjected(DWORD /* PID */, const char* /* moduleName */);
// opens client's process targeted by PID
HANDLE OpenClientProcess(DWORD /* processID */);
// injects a DLL (by location) to the targeted process (by PID)
bool InjectDLL(DWORD /* processID */, const char* /* dllLocation */);

int main(int argc, char* argv[])
{
    if (Program::Is64Bit())
        SetConsoleTitle("Whiff (64 bit)");
    else
        SetConsoleTitle("Whiff (32 bit)");

    Program::Splash();

    if (argc > 2)
    {
        printf("ERROR: Invalid parameters. ");
        printf("Example: \"Whiff.exe [wow_exe_name]\"\n\n");
        system("pause");
        return 0;
    }

    // this process will be injected
    DWORD processID = SelectProcess(argc == 2 ? argv[1] : nullptr);

    if (!processID)
        return 0;

    // stores where the injector is, so location/path of the current process
    char injectorPath[MAX_PATH] = { 0 };
    // gets where the injector is
    DWORD injectorPathSize = GetModuleFileName(NULL, injectorPath, MAX_PATH);
    if (!injectorPathSize)
    {
        printf("ERROR: Can't get the injector's path, ");
        printf("ErrorCode: %u\n\n", GetLastError());
        system("pause");
        return 0;
    }

    // full path of the DLL
    char* dllPath = new char[MAX_PATH];
    // copies injector's full path to dllPath
    strncpy_s(dllPath, MAX_PATH, injectorPath, injectorPathSize);

    // some magic to replace path/Whiff.exe to path/whiff.dll
    // removes injector's name
    PathRemoveFileSpec(dllPath);
    // appends DLL's name
    PathAppend(dllPath, injectDLLName);

    printf("DLL: %s\n", dllPath);

    if (InjectDLL(processID, dllPath))
        printf("\nInjection of '%s' is successful.\n\n", injectDLLName);
    else
        printf("\nInjection of '%s' is NOT successful.\n\n", injectDLLName);

    delete[] dllPath;

    //system("pause");
    return 0;
}

void GetProcessIDsByName(PIDMap& pids, const std::string& processName)
{
    // gets a snapshot from 32 bit processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        printf("ERROR: Can't get snapshot of processes");
        printf("ErrorCode: %u\n", GetLastError());
    }

    // a process entry from a snapshot
    PROCESSENTRY32 processEntry;
    // from MSDN: The calling application must set the
    // dwSize member of PROCESSENTRY32 to the size, in bytes, of the structure.
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    // checks the first process from the snapshot
    if (Process32First(hSnapshot, &processEntry))
    {
        do
        {
            char* exeName = processEntry.szExeFile;
            ctolower(exeName);

            // process found
            if (!strcmp(exeName, processName.c_str()))
                pids[processEntry.th32ProcessID] = std::string(processEntry.szExeFile);
        }
        // loops over the snapshot
        while (Process32Next(hSnapshot, &processEntry));
    }
    CloseHandle(hSnapshot);
}

bool IsProcessAlreadyInjected(DWORD PID, const char* moduleName)
{
    HANDLE clientProcess = OpenClientProcess(PID);
    if (clientProcess)
    {
        // 256 should be more than enough
        HMODULE modules[256];
        // how many bytes needed to store the modules
        DWORD bytesReq = 0;
        if (!EnumProcessModules(clientProcess, modules, sizeof(modules), &bytesReq))
        {
            printf("Can't get process' modules. ErrorCode: %u\n", GetLastError());
            CloseHandle(clientProcess);
            return false;
        }
        // calculates how many modules are loaded by the process
        DWORD modulesCount = bytesReq / sizeof(HMODULE);

        // loops over the modules
        for (DWORD i = 0; i < modulesCount; ++i)
        {
            // full path of the module
            char modulePath[MAX_PATH];
            // gets module's path
            if (GetModuleFileNameEx(clientProcess, modules[i], modulePath, MAX_PATH))
            {
                // path not needed, just file name
                PathStripPath(modulePath);
                // matches, so already injected
                if (!strcmp(modulePath, moduleName))
                {
                    CloseHandle(clientProcess);
                    return true;
                }
            }
        }
    }
    // error?
    else
    {
        printf("Process can't be opened. ");
        printf("So assume that there is no injection.\n");
        CloseHandle(clientProcess);
        return false;
    }
    CloseHandle(clientProcess);
    // not injected
    return false;
}

HANDLE OpenClientProcess(DWORD processID)
{
    // tries to open the targeted process
    // note: don't use PROCESS_ALL_ACCESS
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ |
        PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION |
        PROCESS_CREATE_THREAD, FALSE, processID);
    // error?
    if (!hProcess)
    {
        if (GetLastError() == ERROR_ACCESS_DENIED)
        {
            printf("Process open is failed, ERROR_ACCESS_DENIED.\n");
            printf("Trying to override client's security descriptor (DACL) ");
            printf("and will try a re-open.\n");

            // clients before 12213 (this build doesn't contain) or
            // 11723 (don't have this WoW client so can't check)
            // override theirs security descriptor
            // (set flag PROTECTED_DACL_SECURITY_INFORMATION) so
            // the injector can't simply OpenProcess them
            //
            // because of this the injector modifies the
            // client's security descriptor (DACL) to the injector's one
            // so after that OpenProcess should work

            // "global" var which stores an error code
            DWORD error = 0;

            // ACL header
            PACL dacl;
            // that pointer contains the security descriptor
            PSECURITY_DESCRIPTOR securityDescriptor;

            // gets injector's security descriptor
            error = GetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &securityDescriptor);
            if (error)
            {
                printf("ERROR: Can't get injector's security secriptor, ");
                printf("ErrorCode: %u\n", error);
                return NULL;
            }

            // tries again to open the client process but
            // only with an access wich can override its DACL
            hProcess = OpenProcess(WRITE_DAC, FALSE, processID);
            if (!hProcess)
            {
                LocalFree(securityDescriptor);
                printf("ERROR: Process open is failed with only ");
                printf("WRITE_DAC access, ErrorCode: %u\n", GetLastError());
                return NULL;
            }

            // overrides client's DACL with injector's DACL
            error = SetSecurityInfo(hProcess, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION, 0, 0, dacl, 0);
            if (error)
            {
                LocalFree(securityDescriptor);
                CloseHandle(hProcess);
                printf("ERROR: Can't override client's DACL, ");
                printf("ErrorCode: %u\n", error);
                return NULL;
            }

            // release resources
            LocalFree(securityDescriptor);
            CloseHandle(hProcess);

            // now this should work
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
        }
        // error!
        if (!hProcess)
        {
            printf("ERROR: Process open is failed, ");
            printf("ErrorCode: %u\n", GetLastError());
            return NULL;
        }
    }
    return hProcess;
}

DWORD SelectProcess(const char* processName)
{
    PIDMap pids;
    if (!processName)
    {
        for (char i = 0; i < WOW_PROCESSES; ++i)
        {
            BasicAppInfo const& appInfo = WoWProcesses[i];
            if (Program::Is64Bit() == appInfo.is64)
                GetProcessIDsByName(pids, appInfo.processName);
        }
    }

    if (pids.empty())
    {
        printf("process NOT found.\n");
        system("pause");
        return 0;
    }
    // just one PID found
    else if (pids.size() == 1)
    {
        // we already know it's not empty so we can do this safely
        DWORD processID = pids.begin()->first;
        std::string processName = pids.begin()->second;

        printf("%s process found, PID: %u\n", processName.c_str(), processID);
        // checks this process is already injected or not
        if (IsProcessAlreadyInjected(processID, injectDLLName))
        {
            printf("Process is already injected.\n\n");
            system("pause");
            return 0;
        }
        return processID;
    }
    // size > 1, multiple possible processes
    else
    {
        printf("Multiple processes found.\n");
        printf("Please select one which will be injected.\n\n");

        // stores the PIDs which are already injected
        // so these are "invalid"
        PIDMap injectedPIDs;

        unsigned int idx = 1;
        for (PIDMap::const_iterator itr = pids.begin(); itr != pids.end(); ++itr)
        {
            DWORD pid = itr->first;
            printf("[%u] PID: %u\n", idx++, pid);
            if (IsProcessAlreadyInjected(pid, injectDLLName))
            {
                printf("Already injected!\n\n");
                injectedPIDs[pid] = itr->second;
            }
        }

        // same size: there is no non-injected PID
        if (pids.size() == injectedPIDs.size())
        {
            printf("All the processes are already injected.\n\n");
            system("pause");
            return 0;
        }

        unsigned int selectedIndex = 0;
        // loops until has correct PID
        while (1)
        {
            DWORD processID = 0;
            selectedIndex = 0;

            printf("Please select a process, use [index]: ");
            scanf("%u", &selectedIndex);
            // bigger than max index
            if (selectedIndex > idx - 1)
            {
                printf("Your index is too big, max index is %u.\n", idx - 1);
                continue;
            }
            // 0 or non int used
            else if (selectedIndex == 0)
            {
                printf("Your index is invalid, 1-%u should be used.\n", idx - 1);
                continue;
            }

            // gets PID via index
            PIDMap::const_iterator itr = pids.begin();
            std::advance(itr, selectedIndex - 1);
            processID = itr->first;

            // if already injected
            if (injectedPIDs.find(processID) != injectedPIDs.end())
            {
                printf("This process is already injected. ");
                printf("Please choose a different one.\n");
                continue;
            }

            printf("\n");

            // looks like all good
            return processID;
        }
    }

    return 0;
}

bool InjectDLL(DWORD processID, const char* dllLocation)
{
    // gets a module handler which loaded by the process which
    // should be injected
    HMODULE hModule = GetModuleHandle(loadedModuleName);
    if (!hModule)
    {
        printf("ERROR: Can't get %s's handle, ", loadedModuleName);
        printf("ErrorCode: %u\n", GetLastError());
        system("pause");
        return false;
    }

    // gets the address of an exported function which can load DLLs
    FARPROC loadLibraryAddress = GetProcAddress(hModule, loadDLLFunctionName);
    if (!loadLibraryAddress)
    {
        printf("ERROR: Can't get function %s's address, ", loadDLLFunctionName);
        printf("ErrorCode: %u\n", GetLastError());
        system("pause");
        return false;
    }

    // opens the process which should be injected
    HANDLE hProcess = OpenClientProcess(processID);
    if (!hProcess)
    {
        printf("Process [%u] open is failed.\n", processID);
        system("pause");
        return false;
    }
    printf("\nProcess [%u] is opened.\n", processID);

    // gets the build number
    WORD buildNumber = GetBuildNumberFromProcess(hProcess);
    // error occured
    if (!buildNumber)
    {
        printf("Can't determine build number.\n");
        CloseHandle(hProcess);
        return false;
    }
    printf("Detected build number: %hu\n", buildNumber);

    // allocates memory for the DLL location string
    LPVOID allocatedMemoryAddress = VirtualAllocEx(hProcess, NULL, strlen(dllLocation), MEM_COMMIT, PAGE_READWRITE);
    if (!allocatedMemoryAddress)
    {
        printf("ERROR: Virtual memory allocation is failed, ");
        printf("ErrorCode: %u.\n", GetLastError());
        system("pause");
        CloseHandle(hProcess);
        return false;
    }

    // writes the DLL location string to the process
    // so this is the parameter which will be passed to LoadLibraryA
    if (!WriteProcessMemory(hProcess, allocatedMemoryAddress, dllLocation, strlen(dllLocation), NULL))
    {
        printf("ERROR: Process memory writing is failed, ");
        printf("ErrorCode: %u\n", GetLastError());
        system("pause");
        VirtualFreeEx(hProcess, allocatedMemoryAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // creates a thread that runs in the virtual address space of
    // the process which should be injected and gives the
    // parameter (allocatedMemoryAddress) to LoadLibraryA(loadLibraryAddress)
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddress, allocatedMemoryAddress, 0, NULL);
    if (!hRemoteThread)
    {
        printf("ERROR: Remote thread creation is failed, ");
        printf("ErrorCode: %u\n", GetLastError());
        system("pause");
        VirtualFreeEx(hProcess, allocatedMemoryAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // waits until the DLL's main function returns
    WaitForSingleObject(hRemoteThread, INFINITE);

    // frees resources
    VirtualFreeEx(hProcess, allocatedMemoryAddress, 0, MEM_RELEASE);
    CloseHandle(hRemoteThread);
    CloseHandle(hProcess);

    return true;
}
