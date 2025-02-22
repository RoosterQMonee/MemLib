#include <Windows.h>
#include <iostream>
#include <cstdio>
#include <TlHelp32.h>
#include <psapi.h>

#include <MemLib/MemLib.h>

std::shared_ptr<MemLib::Hook<MemLib::DirectAddress>> actor_hook;

class Actor;

void ActorBaseTickHk(Actor* act) {
    std::cout << "Actor::BaseTick called!" << std::endl;
    MemLib::call_func<void, Actor*>(
        actor_hook->originalFunction,
        act
    );
}

void Main() {
    FILE* fDummy;
    AllocConsole();
    AttachConsole(GetCurrentProcessId());
    freopen_s(&fDummy, "CONIN$", "r", stdin);
    freopen_s(&fDummy, "CONOUT$", "w", stderr);
    freopen_s(&fDummy, "CONOUT$", "w", stdout);
    HANDLE hConOut = CreateFile(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    SetStdHandle(STD_OUTPUT_HANDLE, hConOut);
    SetConsoleTitleA("Debug Console");

    printf("CPU Features: %s\n", MemLib::scanner.get_detected_cpu_features().c_str());

    const char* pattern = "48 8B C4 48 89 58 ? 48 89 70 ? 57 48 81 EC ? ? ? ? 0F 29 70 ? 0F 29 78 ? 44 0F 29 40 ? 44 0F 29 48 ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 44 24 ? 41 0F B6 F0";
    std::optional<DWORD64> opt_base_addr = MemLib::Module::get_module_base("Minecraft.Windows.exe");
    DWORD64 length = MemLib::Module::get_module_size("Minecraft.Windows.exe").value();

    if (!opt_base_addr.has_value()) {
        printf("Failed to get module base\n");
        return;
    }

    void* base_addr = reinterpret_cast<void*>(opt_base_addr.value());

    // Use SSE optimizations
    printf("> Signature scanning with SSE\n");
    auto result = MemLib::scanner.custom_scan_pattern<MemLib::InstructionSet::SSE>(pattern, base_addr, length);
    if (result) {
        printf("Found pattern at address: %p\n", result->address);
        printf("Module base: %p\n", reinterpret_cast<void*>(result->module_base));
        printf("Module size: %zu bytes\n", result->module_size);
    }

    // Basic scanning
    printf("> Signature scanning with Fallback\n");
    auto fbresult = MemLib::scanner.custom_scan_pattern<MemLib::InstructionSet::NONE>(pattern, base_addr, length);
    if (fbresult) {
        printf("Found pattern at address: %p\n", fbresult->address);
        printf("Module base: %p\n", reinterpret_cast<void*>(fbresult->module_base));
        printf("Module size: %zu bytes\n", fbresult->module_size);
    }

    // Get module size
    auto size = MemLib::Module::get_module_size(reinterpret_cast<HMODULE>(base_addr)).value();
    if (size) {
        printf("Module size: 0x%016llX\n", size);
    }

    // Parse exports
    auto exports = MemLib::Module::parse_export_table(reinterpret_cast<HMODULE>(base_addr));
    printf("Found %zu exports:\n", exports.size());
    for (const auto& exp : exports) {
        printf("  %s (ordinal: %u)\n", exp.name.c_str(), exp.ordinal);
    }

    // Parse imports
    /*
    auto imports = MemLib::Module::parse_import_table(reinterpret_cast<HMODULE>(base_addr));
    printf("Found %zu imports:\n", imports.size());
    for (const auto& imp : imports) {
        printf("  DLL: %s\n", imp.dll_name.c_str());
        printf("    Functions:\n");
        for (const auto& func : imp.functions) {
            printf("      %s\n", func.c_str());
        }
    }
    */

    // Analyze sections
    auto sections = MemLib::Module::analyze_sections(reinterpret_cast<HMODULE>(base_addr));
    printf("Found %zu sections:\n", sections.size());
    for (const auto& sec : sections) {
        printf("  %s\n", sec.name.c_str());
        printf("    Virtual Size: 0x%08X\n", sec.virtual_size);
        printf("    Virtual Address: 0x%08X\n", sec.virtual_address);
        printf("    Raw Data Size: 0x%08X\n", sec.size_of_raw_data);
        printf("    Characteristics: 0x%08X\n", sec.characteristics);
    }

    std::cout.clear();

    // Find export(s)
    MemLib::SymbolSearchResult sresult = MemLib::Module::find_function_by_export(GetModuleHandleA("user32.dll"), "MessageBoxA");
    if (sresult.found) {
        std::cout << "Found function: " << sresult.symbolName
                  << "\nRVA: " << std::hex << sresult.rva
                  << "\nSymbol: " << sresult.symbolName << std::endl;

        //typedef int (WINAPI* MyFunction)(HWND, LPCSTR, LPCSTR, UINT);
        //MyFunction myFunction = (MyFunction)sresult.rva;
        //(*myFunction)(0, "MessageBoxA from MemLib!", 0, 0);
    }

    // Hook functions
    MemLib::HookManager hm;
    hm.Init();

    auto scan = MemLib::scanner.custom_scan_pattern<MemLib::InstructionSet::NONE>(
        "48 8D 05 ? ? ? ? 48 89 01 BA 33 00 00 00 44 8D 4A 04 44 8D 42 02 66 C7 44 24 20 39 00 E8 ? ? ? ? 48 8B 8F 28 11 00 00",
        base_addr,
        length
    );

    if (!scan.has_value())
        printf("Cannot find signature!\n");
    else {
        printf("Found signature at: %p\n", scan.value().address);

        uintptr_t base = scan.value().address;
        int offset = *reinterpret_cast<int*>(base + 3);
        uintptr_t** vft = reinterpret_cast<uintptr_t**>(base + offset + 7);

        printf("Vft[24] at: %p\n", vft[24]);

        actor_hook = hm.AddHook<MemLib::DirectAddress>("Actor::BaseTick", "", vft[24], &ActorBaseTickHk);
        hm.EnableAll((void*)scan.value().module_base, 0);
    }
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(Main), nullptr, 0, nullptr);
    }
    return TRUE;
}

