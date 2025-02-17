# MemLib

A basic Header-Only C++20 modding library!
> Check out `dllmain.cpp` for examples on MC:BE 1.21.60!

### Features

**Signature Scanning**
```
// Auto-detect method
auto result = MemLib::scanner.scan_pattern(pattern, base_addr, length);

// Choose a custom method
auto result = MemLib::scanner.custom_scan_pattern<MemLib::InstructionSet::SSE>(pattern, base_addr, length);
```

**Module Utils**
```
auto module_base = MemLib::Module::get_module_base("Minecraft.Windows.exe");
auto module_size = MemLib::Module::get_module_size("Minecraft.Windows.exe");

auto message_box = MemLib::Module::find_function_by_export(GetModuleHandleA("user32.dll"), "MessageBoxA");
auto sections = MemLib::Module::analyze_sections(reinterpret_cast<HMODULE>(module_base));
auto exports = MemLib::Module::parse_export_table(reinterpret_cast<HMODULE>(module_base));
```

**Hook Management**
```
MemLib::HookManager manager;
manager.Init();

auto actor_hook = manager.AddHook<MemLib::DirectAddress>("Hook::Name", &hookAddress, &callbackFunction); // pre-calculated address
auto actor_hook = manager.AddHook<MemLib::Signature>("Hook::Name", "48 8D ? ? ?", &callbackFunction);    // scan signature on enable
auto actor_hook = manager.AddHook<MemLib::Independent>("Hook::Name", &callbackFunction);                 // custom enable (e.g. keiro)
manager.EnableAll(module_base, module_size);
```

### To-Do:

> Clean up `Hook` and `HookBase` class

> Make classes and structs use simular types

> Use a more consistent code style

> Fix **AVX512** scanning

> Fix `Module::parse_import_table`

> Minimize stack usage in `Module::find_function_by_export`