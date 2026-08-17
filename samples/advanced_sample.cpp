#include <iostream>
#include <fstream>
#include <vector>
#include <cstdlib>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

int main() {
    std::cout << "[*] Advanced Sample Binary Started." << std::endl;

    // 1. File Activity: Create and write dropped file in Temp directory
    std::cout << "[+] Performing File System Operations..." << std::endl;
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    std::string dropFile = std::string(tempPath) + "sandbox_dropped_payload.txt";

    std::ofstream ofs(dropFile);
    if (ofs.is_open()) {
        ofs << "CRITICAL_PAYLOAD_DATA: MALICIOUS_SIGNATURE_DEMO_2026\n";
        ofs.close();
        std::cout << "[+] Created dropped file: " << dropFile << std::endl;
    }

    // 2. Child Process Activity: Launch whoami via cmd.exe
    std::cout << "[+] Spawning Child Process (cmd.exe /c whoami)..." << std::endl;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    char cmd[] = "cmd.exe /c whoami";
    if (CreateProcessA(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 3000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        std::cout << "[+] Child process completed." << std::endl;
    }

    // 3. Network Activity: Outbound TCP probe
    std::cout << "[+] Performing Network Socket Connect (Google DNS 8.8.8.8:53)..." << std::endl;
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) == 0) {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s != INVALID_SOCKET) {
            sockaddr_in target;
            target.sin_family = AF_INET;
            target.sin_port = htons(53);
            inet_pton(AF_INET, "8.8.8.8", &target.sin_addr);

            // Quick non-blocking connect attempt
            u_long mode = 1;
            ioctlsocket(s, FIONBIO, &mode);
            connect(s, reinterpret_cast<sockaddr*>(&target), sizeof(target));
            Sleep(500);
            closesocket(s);
            std::cout << "[+] Network socket operation completed." << std::endl;
        }
        WSACleanup();
    }

    std::cout << "[*] Advanced Sample Execution Completed Successfully." << std::endl;
    return 0;
}
