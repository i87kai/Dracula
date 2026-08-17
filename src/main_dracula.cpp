// ============================================================================
//  main_dracula.cpp  –  Dracula Unified Binary Intelligence Platform
// ============================================================================

#include "cli/dracula_shell.h"
#include "common/config.h"

int main(int argc, char* argv[]) {
    // 1. Load configuration defaults
    Dracula::ConfigManager::Instance().LoadFromFile("config/config.ini");

    // 2. Dispatch interactive shell or CLI flag execution
    Dracula::DraculaShell shell;
    return shell.ProcessArgs(argc, argv);
}
