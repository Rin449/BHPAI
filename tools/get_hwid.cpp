#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <sstream>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

static std::string GetRegistryValue(HKEY root, const std::wstring& subkey, const std::wstring& value_name) {
    HKEY hKey = nullptr;
    // Try 64-bit view first
    if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) {
        if (RegOpenKeyExW(root, subkey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            return "UNKNOWN_MACHINE_GUID";
        }
    }

    wchar_t buffer[512] = {0};
    DWORD buffer_size = sizeof(buffer);
    DWORD type = 0;
    std::string result = "UNKNOWN_MACHINE_GUID";

    if (RegQueryValueExW(hKey, value_name.c_str(), nullptr, &type, reinterpret_cast<LPBYTE>(buffer), &buffer_size) == ERROR_SUCCESS) {
        int len = WideCharToMultiByte(CP_UTF8, 0, buffer, -1, nullptr, 0, nullptr, nullptr);
        if (len > 0) {
            std::vector<char> str(len);
            WideCharToMultiByte(CP_UTF8, 0, buffer, -1, str.data(), len, nullptr, nullptr);
            result = std::string(str.data());
        }
    }
    RegCloseKey(hKey);
    return result;
}

static std::string GetDriveVolumeSerial(const std::wstring& drive = L"C:\\") {
    DWORD serial_number = 0;
    if (GetVolumeInformationW(drive.c_str(), nullptr, 0, &serial_number, nullptr, nullptr, nullptr, 0)) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%08x", serial_number);
        return std::string(buf);
    }
    return "00000000";
}

static std::string GetProcessorIdentifier() {
    wchar_t buffer[512] = {0};
    DWORD len = GetEnvironmentVariableW(L"PROCESSOR_IDENTIFIER", buffer, 512);
    if (len > 0) {
        int utf8_len = WideCharToMultiByte(CP_UTF8, 0, buffer, -1, nullptr, 0, nullptr, nullptr);
        if (utf8_len > 0) {
            std::vector<char> str(utf8_len);
            WideCharToMultiByte(CP_UTF8, 0, buffer, -1, str.data(), utf8_len, nullptr, nullptr);
            return std::string(str.data());
        }
    }
    return "GENERIC_CPU";
}

static std::string Sha256Hex(const std::string& input) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status != 0) return "";

    status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
    if (status != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return "";
    }

    BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<char*>(input.data())), static_cast<ULONG>(input.size()), 0);

    unsigned char hash[32];
    BCryptFinishHash(hHash, hash, sizeof(hash), 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    std::ostringstream oss;
    for (int i = 0; i < 32; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return oss.str();
}

static std::string ComputeHWID() {
    std::string guid = GetRegistryValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");
    std::string vol = GetDriveVolumeSerial(L"C:\\");
    std::string proc = GetProcessorIdentifier();

    std::string raw = guid + ":" + vol + ":" + proc;
    std::transform(raw.begin(), raw.end(), raw.begin(), ::toupper);

    // Trim whitespace
    raw.erase(0, raw.find_first_not_of(" \t\r\n"));
    raw.erase(raw.find_last_not_of(" \t\r\n") + 1);

    return Sha256Hex(raw);
}

static bool CopyToClipboard(const std::string& text) {
    if (!OpenClipboard(nullptr)) return false;
    EmptyClipboard();
    HGLOBAL hGlob = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    if (!hGlob) {
        CloseClipboard();
        return false;
    }
    memcpy(GlobalLock(hGlob), text.c_str(), text.size() + 1);
    GlobalUnlock(hGlob);
    SetClipboardData(CF_TEXT, hGlob);
    CloseClipboard();
    return true;
}

int main(int argc, char* argv[]) {
    // Check arguments
    bool raw_mode = false;
    bool json_mode = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--raw" || arg == "-r") raw_mode = true;
        else if (arg == "--json") json_mode = true;
    }

    std::string hwid = ComputeHWID();
    bool copied = CopyToClipboard(hwid);

    if (raw_mode) {
        std::cout << hwid << "\n";
        return 0;
    }

    if (json_mode) {
        std::cout << "{\"hwid\":\"" << hwid << "\",\"copied\":" << (copied ? "true" : "false") << "}\n";
        return 0;
    }

    // Set console output code page to UTF-8
    SetConsoleOutputCP(CP_UTF8);

    std::cout << "\n==================================================================\n";
    std::cout << "  BHPAI Device Identifier & Hardware ID (HWID) Tool v1.6.0\n";
    std::cout << "==================================================================\n";
    std::cout << " Mã máy (HWID) : " << hwid << "\n";
    std::cout << "------------------------------------------------------------------\n";
    if (copied) {
        std::cout << " [+] DA TU DONG SAO CHEP MA HWID VAO CLIPBOARD (Bo nho tam)!\n";
    }
    std::cout << " [*] Vui long dan (Ctrl+V) ma nay vao Web Portal:\n";
    std::cout << "     https://bhpai.io/license (hoac trang /license tren trinh duyet)\n";
    std::cout << "     de cap va tai file license.dat ve may.\n";
    std::cout << "==================================================================\n\n";

    // If launched by double-clicking in Explorer (no redirected stdin)
    // Wait for user input so the window doesn't immediately close
    DWORD procList[2] = {0};
    if (GetConsoleProcessList(procList, 2) <= 1) {
        std::cout << "Nhan Enter de thoat...";
        std::cin.get();
    }

    return 0;
}
