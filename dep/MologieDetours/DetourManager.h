#pragma once
#ifndef DETOUR_MGR
#define DETOUR_MGR

#include "Define.h"
#include "detours.h"

enum Hooks
{
    HOOK_SEND2,
    HOOK_PROCESSMESSAGE,
    HOOK_MESSAGEREADY,
    HOOK_HANDLEDATA,
    HOOK_CDGETINT32,
};

class DetourManager
{
    DetourManager() { }
    ~DetourManager()
    {
        Clear();
    }

    std::map<Hooks, Detours::DetourBase*> _detours;
    std::string _lastError;
public:
    static DetourManager* instance()
    {
        static DetourManager instance;
        return &instance;
    }

    template<class T> Detours::Detour<T>* GetDetour(Hooks hook)
    {
        return reinterpret_cast<Detours::Detour<T>*>(_detours[hook]);
    }

    bool HasDetour(Hooks hook)
    {
        return _detours.find(hook) != _detours.end();
    }

    void Clear()
    {
        for (auto i = _detours.begin(); i != _detours.end(); ++i)
            delete i->second;
        _detours.clear();
    }

    template<class T> bool CreateDetour(Hooks hook, ADDRESS offset, T detour, bool rebase = true)
    {
        if (_detours.find(hook) != _detours.end())
            return false;

        try
        {
            if (rebase)
                _detours[hook] = new Detours::Detour<T>((T)EXE_REBASE(offset), detour);
            else
                _detours[hook] = new Detours::Detour<T>((T)offset, detour);
            return true;
        }
        catch (Detours::DetourException& e)
        {
            _lastError = e.what();
            return false;
        }
    }

    std::string const& GetLastError() const
    {
        return _lastError;
    }

    bool RemoveDetour(Hooks hook)
    {
        if (_detours.find(hook) != _detours.end())
        {
            delete _detours[hook];
            _detours.erase(hook);
            return true;
        }
        return false;
    }
};

#define sDetourMgr DetourManager::instance()

#endif // DETOUR_MGR
