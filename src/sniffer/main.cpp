
#include "Define.h"
#include "ConsoleManager.h"
#include "Sniffer.h"
#include "HexSearcher.h"
#include "OpcodeMgr.h"
#include "CommandMgr.h"
#include "SnifferConsole.h"
#include "DetourManager.h"

volatile bool* ConsoleManager::_sniffingLoopCondition = NULL;

// needed to correctly shutdown the sniffer
HINSTANCE instanceDLL = NULL;

// true when a SIGINT occured
volatile bool isSigIntOccured = false;

// basically this method controls what the sniffer should do
// pretty much like a "main method"
DWORD MainThreadControl(LPVOID /* param */);

// entry point of the DLL
BOOL APIENTRY DllMain(HINSTANCE instDLL, DWORD reason, LPVOID /* reserved */)
{
    // called when the DLL is being loaded into the
    // virtual address space of the current process (where to be injected)
    if (reason == DLL_PROCESS_ATTACH)
    {
        instanceDLL = instDLL;
        // disables thread notifications (DLL_THREAD_ATTACH, DLL_THREAD_DETACH)
        DisableThreadLibraryCalls(instDLL);

        // creates a thread to execute within the
        // virtual address space of the calling process (WoW)
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&MainThreadControl, NULL, 0, NULL);
    }
    // the DLL is being unloaded
    else if (reason == DLL_PROCESS_DETACH)
    {
        // close the dump file
        sSniffer->CloseFileDump();

        // deallocates the console
        ConsoleManager::Destroy();
    }
    return TRUE;
}

DWORD MainThreadControl(LPVOID /* param */)
{
    // creates the console
    if (!ConsoleManager::Create(&isSigIntOccured))
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);

    Program::Splash();

    DWORD buildNumber = GetBuildNumberFromProcess();
    if (!buildNumber)
    {
        printf("ERROR: Can't determine build number.\n\n");
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }
    printf("Detected build: %hu\n", buildNumber);

    sSniffer->SetBuild(buildNumber);

    ClientAddresses::InitAddresses();
    ClientAddresses::Addresses* addresses = ClientAddresses::GetFuncAddresses(buildNumber);

    addresses = sHexSearcher->GetAddresses(addresses);
    if (!addresses)
    {
        printf("ERROR: One or more required addresses weren't found\n");
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }

    // gets the location of the DLL
    char dllPath[MAX_PATH] = { 0 };
    DWORD dllPathSize = GetModuleFileName((HMODULE)instanceDLL, dllPath, MAX_PATH);
    if (!dllPathSize)
    {
        printf("\nERROR: Can't get the injected DLL's location, ");
        printf("ErrorCode: %u\n\n", GetLastError());
        system("pause");
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    }

    sSniffer->InitSnifferInfo(std::string(dllPath), addresses);
    sSniffer->GetLocale();
    sOpcodeMgr->Initialize();
    sOpcodeMgr->LoadOpcodeFile(instanceDLL); // must be called after Initialize()
    sCommandMgr->InitCommands();

    SnifferConsole* snifferConsole = new SnifferConsole();

    if (!sSniffer->InitHooks())
        FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);

    snifferConsole->SetActive();
    // loops until SIGINT (CTRL-C) occurs or quit is called
    while (!isSigIntOccured && !Sniffer::IsStopped())
    {
        snifferConsole->ProcessCliCommands();
        Sleep(50); // sleeps 50 ms to be nice
    }

    snifferConsole->ShutDown();
    sOpcodeMgr->ShutDown();
    sCommandMgr->ClearCommands();
    ClientAddresses::FreeAddresses();
    delete snifferConsole;
    sDetourMgr->Clear();

    FreeLibraryAndExitThread((HMODULE)instanceDLL, 0);
    return 0;
}
