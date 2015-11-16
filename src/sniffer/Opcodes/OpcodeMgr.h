#ifndef _OpcodeMgr_h__
#define _OpcodeMgr_h__

#include "Define.h"

struct OpcodeHandler
{
    OpcodeHandler() {}

    OpcodeHandler(unsigned int opcodeNumber, const std::string& _name)
        : OpcodeNumber(opcodeNumber), Name(_name) {}

    std::string Name;
    unsigned int OpcodeNumber;
};

class OpcodeTable
{
public:
    OpcodeTable() { }

    ~OpcodeTable()
    {
        while (!_internalTable.empty())
        {
            Opcodes::iterator opcode = _internalTable.begin();
            delete opcode->second;
            _internalTable.erase(opcode);
        }
    }

    void CreateOpcodeHandler(unsigned int opcode, const std::string& name) { _internalTable[opcode] = new OpcodeHandler(opcode, name); }
    OpcodeHandler* const GetOpcodeHandler(unsigned int opcode) const
    {
        Opcodes::const_iterator itr = _internalTable.find(opcode);
        if (itr != _internalTable.end())
            return itr->second;

        return nullptr;
    }

    size_t size() { return _internalTable.size(); }

private:

    // Prevent copying this structure
    OpcodeTable(OpcodeTable const&);
    OpcodeTable& operator=(OpcodeTable const&);

    typedef std::unordered_map<unsigned int, OpcodeHandler*> Opcodes;
    Opcodes _internalTable;
};

class OpcodeMgr
{
    public:
        static OpcodeMgr* instance()
        {
            static OpcodeMgr instance;
            return &instance;
        }

        void Initialize();
        void ShutDown();
        void ValidateAndSetOpcode(const std::string& name, unsigned int opcodeNumber);
        void LoadOpcodeFile(const HINSTANCE moduleHandle);

        bool ShouldShowOpcode(unsigned int opcode, DWORD64 packetType);
        bool IsKnownOpcode(unsigned int opcode, bool isServerOpcode);
        bool IsBlocked(unsigned int opcode, bool serverOpcode);
        void BlockOpcode(unsigned int opcode, unsigned short type) { m_blockedOpcodes[type].insert(opcode); }
        void UnBlockOpcode(unsigned int opcode, unsigned short type) { m_blockedOpcodes[type].erase(opcode); }
        void UnBlockAll(unsigned int type);
        bool ShowKnownOpcodes() { return m_showKnownOpcodes; }
        bool ShowOpcodeType(DWORD64 type);
        void ToggleKnownOpcodes() { m_showKnownOpcodes = !m_showKnownOpcodes; }
        void ToggleClientOpcodes() { m_showClientOpcodes = !m_showClientOpcodes; }
        void ToggleServerOpcodes() { m_showServerOpcodes = !m_showServerOpcodes; }
        void AddExclusiveOpcode(unsigned int opcode, unsigned short type) { m_exclusiveOpcodes[type].insert(opcode); }
        void DelExclusiveOpcode(unsigned int opcode, unsigned short type) { m_exclusiveOpcodes[type].erase(opcode); }
        void ClearExclusive(unsigned short type);
        bool HasExclusive() { return !m_exclusiveOpcodes[0].empty() || !m_exclusiveOpcodes[1].empty(); }
        bool IsExclusive(unsigned int opcode, unsigned short type);

        std::string GetOpcodeNameForLogging(unsigned int opcode, bool isServerOpcode);

        size_t GetNumCliOpcodes() { return clientOpcodeTable->size(); }
        size_t GetNumServerOpcodes() { return serverOpcodeTable->size(); }

    private:
        OpcodeMgr() { }
        ~OpcodeMgr() { }

        OpcodeTable* serverOpcodeTable;
        OpcodeTable* clientOpcodeTable;

        typedef std::set<unsigned int> OpcodeSet;
        OpcodeSet m_blockedOpcodes[2];
        OpcodeSet m_exclusiveOpcodes[2];

        bool m_showKnownOpcodes;
        bool m_showClientOpcodes;
        bool m_showServerOpcodes;
};

#define sOpcodeMgr OpcodeMgr::instance()

#endif // _OpcodeMgr_h__