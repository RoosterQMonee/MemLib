#include <Windows.h>
#include <iostream>
#include <cstdio>
#include <TlHelp32.h>
#include <psapi.h>

#include <memlib/MemLib.h>

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
    auto imgonnalosemyfuckingmindoverthis = MemLib::Module::find_function_by_export(MemLib::Module::get_module_base("user32.dll").value(), "MessageBoxA");
    if (imgonnalosemyfuckingmindoverthis.has_value()) {
        typedef int (WINAPI* MyFunction)(HWND, LPCSTR, LPCSTR, UINT);
        auto myFunction = (MyFunction)imgonnalosemyfuckingmindoverthis.value().address;
        (*myFunction)(0, "DllMain is being called...", 0, 0);
    }

    FILE* fDummy;

    if (!AllocConsole())
    {
        OutputDebugStringA("Failed to allocate console\n");
        return;
    }

    if (!AttachConsole(GetCurrentProcessId()))
    {
        FreeConsole();
        OutputDebugStringA("Failed to attach to console\n");
        return;
    }

    freopen_s(&fDummy, "CONOUT$", "w", stdout);
    freopen_s(&fDummy, "CONOUT$", "w", stderr);
    freopen_s(&fDummy, "CONIN$", "r", stdin);

    if (std::cout.fail())
    {
        OutputDebugStringA("Failed to initialize stdout\n");
        return;
    }

    HANDLE hConOut = CreateFile(reinterpret_cast<LPCSTR>(L"CONOUT$"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    SetStdHandle(STD_OUTPUT_HANDLE, hConOut);
    SetConsoleTitleA("Debug Console");

    printf("CPU Features: %s\n", MemLib::scanner.get_detected_cpu_features().c_str());

    const auto pattern = "48 8B C4 48 89 58 ? 48 89 70 ? 57 48 81 EC ? ? ? ? 0F 29 70 ? 0F 29 78 ? 44 0F 29 40 ? 44 0F 29 48 ? 48 8B 05 ? ? ? ? 48 33 C4 48 89 44 24 ? 41 0F B6 F0";
    const std::optional<DWORD64> opt_base_addr = MemLib::Module::get_module_base("Minecraft.Windows.exe");
    const std::optional<DWORD64> opt_length = MemLib::Module::get_module_size("Minecraft.Windows.exe");

    if (!opt_base_addr.has_value()) {
        printf("Failed to get module base\n");
        return;
    }

    if (!opt_length.has_value()) {
        printf("Failed to get module size\n");
        return;
    }

    const auto base_addr = reinterpret_cast<void*>(opt_base_addr.value());
    const auto length = opt_length.value();

    // Use SSE optimizations
    printf("> Signature scanning with SSE\n");
    if (const auto result = MemLib::Scanner::custom_scan_pattern<MemLib::InstructionSet::SSE>(pattern, base_addr, length)) {
        printf("Found pattern at address: %llu\n", result->address);
        printf("Module base: %p\n", reinterpret_cast<void*>(result->module_base));
        printf("Module size: %zu bytes\n", result->module_size);
    }

    // Basic scanning
    printf("> Signature scanning with Fallback\n");
    if (const auto fbresult = MemLib::Scanner::custom_scan_pattern<MemLib::InstructionSet::NONE>(pattern, base_addr, length)) {
        printf("Found pattern at address: %llu\n", fbresult->address);
        printf("Module base: %p\n", reinterpret_cast<void*>(fbresult->module_base));
        printf("Module size: %zu bytes\n", fbresult->module_size);
    }

    // Get module size
    if (const auto size = MemLib::Module::get_module_size("Minecraft.Windows.exe").value()) {
        printf("Module size: 0x%016llX\n", size);
    }

    // Parse exports
    auto exports = MemLib::Module::parse_export_table(static_cast<HMODULE>(base_addr));
    printf("Found %zu exports:\n", exports.value().size());
    for (const auto& exp : exports.value()) {
        printf("  %s (ordinal: %u)\n", exp.name.c_str(), exp.ordinal);
    }

    // Analyze sections
    const auto sections = MemLib::Module::analyze_sections(static_cast<HMODULE>(base_addr));
    printf("Found %zu sections:\n", sections.size());
    for (const auto& sec : sections) {
        printf("  %s\n", sec.name.c_str());
        printf("    Virtual Size: 0x%08X\n", sec.virtual_size);
        printf("    Virtual Address: 0x%08X\n", sec.virtual_address);
        printf("    Raw Data Size: 0x%08X\n", sec.size_of_data);
        printf("    Characteristics: 0x%08X\n", sec.characteristics);
    }

    std::cout.clear();

    // Find export(s)
    auto sresult = MemLib::Module::find_function_by_export(MemLib::Module::get_module_base("user32.dll").value(), "MessageBoxA");
    if (sresult.has_value()) {
        std::cout << "Found function: " << sresult->name
                  << "\nRVA: " << std::hex << sresult->rva
                  << "\nSymbol: " << sresult->name << std::endl;

        typedef int (WINAPI* MyFunction)(HWND, LPCSTR, LPCSTR, UINT);
        auto myFunction = (MyFunction)sresult.value().address;
        (*myFunction)(0, "MessageBoxA from MemLib!", 0, 0);
    }

    // Hook functions
    MemLib::HookManager hm;
    hm.Init();

    const auto scan = MemLib::Scanner::custom_scan_pattern<MemLib::InstructionSet::NONE>(
        "48 8D 05 ? ? ? ? 48 89 01 BA 33 00 00 00 44 8D 4A 04 44 8D 42 02 66 C7 44 24 20 39 00 E8 ? ? ? ? 48 8B 8F 28 11 00 00",
        base_addr,
        length
    );

    if (!scan.has_value())
        printf("Cannot find signature!\n");
    else {
        printf("Found signature at: %llu\n", scan.value().address);

        const uintptr_t base = scan.value().address;
        const int offset = *reinterpret_cast<int*>(base + 3);
        const auto vft = reinterpret_cast<uintptr_t**>(base + offset + 7);

        printf("Vft[24] at: %p\n", vft[24]);

        actor_hook = hm.AddHook<MemLib::DirectAddress>("Actor::BaseTick", "", vft[24], reinterpret_cast<void*>(&ActorBaseTickHk));
        hm.EnableAll(reinterpret_cast<void *>(scan.value().module_base), 0);
    }
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(Main), nullptr, 0, nullptr);
    }
    return TRUE;
}

