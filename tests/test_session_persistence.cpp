#include "utr/session_manager.h"
#include "common/paths.h"
#include <iostream>
#include <cassert>

using namespace Dracula::UTR;

int main() {
    std::cout << "[Test] Running SQLite Session Persistence Suite...\n";

    SessionManager& sm = SessionManager::Instance();
    assert(sm.Initialize());

    // Create session
    TargetInfo target;
    target.name = "test_persistence.exe";
    target.path = "C:\\Windows\\System32\\notepad.exe";
    target.kind = TargetKind::NativeExe;
    target.architecture = "x64";
    target.sha256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";

    uint32_t sessionId = sm.CreateSession(target);
    assert(sessionId > 0);
    std::cout << "  Created session ID: " << sessionId << "\n";

    auto list = sm.ListSessions();
    assert(!list.empty());
    std::cout << "  Total active sessions in DB: " << list.size() << "\n";

    // Switch session
    assert(sm.SwitchSession(sessionId));
    assert(sm.GetActiveSessionId() == sessionId);

    std::cout << "[Test] Session Persistence Suite PASSED!\n";
    return 0;
}
