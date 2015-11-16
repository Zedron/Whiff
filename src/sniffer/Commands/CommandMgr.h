#ifndef _CommandMgr_h__
#define _CommandMgr_h__

#include <string>

class CommandMgr
{
    public:
        static CommandMgr* instance()
        {
            static CommandMgr instance;
            return &instance;
        }

        void InitCommands();
        void ClearCommands();
        bool HandleCommand(const std::string& command, char* args[]);
        unsigned int GetOpcodeFromParam(char* param);

        int IsServerIdentifier(char* param);

    private:
        bool HandleQuitCommand(char* args[]);
        bool HandleBlockCommand(char* args[]);
        bool HandleUnblockCommand(char* args[]);
        bool HandleToggleCommand(char* args[]);
        bool HandleExclusiveCommand(char* args[]);
        bool HandleHelpCommand(char* args[]);

};
#define sCommandMgr CommandMgr::instance()

#endif
