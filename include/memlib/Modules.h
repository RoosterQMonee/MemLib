#pragma once

#include <Windows.h>

#include <optional>
#include <string>
#include <vector>

#include "Memory.h"
#include "Types.h"

namespace MemLib {
  /**
   * @brief Struct containing information about module section headers
   */
  struct SectionHeader {
    std::string name;
    Types::UL virtual_size{};
    Types::UL virtual_address{};
    Types::UL size_of_data{};
    Types::UL pointer_to_data{};
    Types::UL characteristics{};
  };

  /**
   * @brief Struct that holds information about a module export
   */
  struct ExportEntry {
    std::string name;
    Types::UL ordinal{};
    Types::UL address{};
  };

  /**
   * @brief Struct that holds information about a module import
   */
  struct ImportEntry {
    std::string name;
    std::vector<std::string> functions;
  };

  /**
   * @brief Struct that holds returned information from an export/symbol scan
   */
  struct SymbolSearchResult {
    std::string name;
    Types::UL* address;
    Types::UL rva;
  };

  /**
   * @brief A class containing basic utilities for modules
   */
  class Module {
    /**
     * @brief Find an export from a module by a string
     * @param peBase The base address of the module
     * @param export_name The name of the export
     * @return A SymbolSearchResult struct containing the export information
     */
    static std::optional<SymbolSearchResult> find_function_by_export(Types::UL peBase, const std::string_view export_name) {
      std::optional<SymbolSearchResult> result = std::nullopt;

      if (peBase == 0)
        return result;

      const auto imageDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(peBase);
      if (imageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return result;

      const auto imageNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(imageDosHeader + imageDosHeader->e_lfanew);
      if (imageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return result;

      const auto imageOptionalHeader = &imageNtHeaders->OptionalHeader;
      const auto imageExportDataDirectory
          = &imageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
      const auto imageExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
          peBase + imageExportDataDirectory->VirtualAddress);

      const Types::UL numberOfNames = imageExportDirectory->NumberOfNames;

      const auto exportAddressTable
          = reinterpret_cast<Types::UL*>(peBase + imageExportDirectory->AddressOfFunctions);
      const auto nameOrdinalsPointer
          = reinterpret_cast<Types::US*>(peBase + imageExportDirectory->AddressOfNameOrdinals);
      const auto exportNamePointerTable
          = reinterpret_cast<Types::UL*>(peBase + imageExportDirectory->AddressOfNames);

      int nameIndex = 0;
      for (nameIndex = 0; nameIndex < numberOfNames; nameIndex++)
      {
        if (const char* name = reinterpret_cast<char*>(peBase + exportNamePointerTable[nameIndex]);
            export_name == name)
        {
          const Types::UL ordinal = nameOrdinalsPointer[nameIndex];
          const auto targetFunctionAddress = reinterpret_cast<Types::UL*>(peBase + exportAddressTable[ordinal]);

          result->rva = *targetFunctionAddress;
          result->name = name;
          result->address = reinterpret_cast<Types::UL*>(peBase);
          return result;
        }
      }

      return result;
    }

    /**
     * @brief Find all exports from a module
     * @param hModule The modules handle
     * @return A vector of ExportEntry structs pointing to exports
     */
    static std::optional<std::vector<ExportEntry>> parse_export_table(HMODULE hModule) {
      std::optional<std::vector<ExportEntry>> result = std::nullopt;

      if (!hModule) return result;

      const auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
      if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return result;

      const Types::UL64 ntOffset = dosHeader->e_lfanew;
      if (ntOffset == 0 || ntOffset > 0x1000) return result;

      const auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
      reinterpret_cast<Types::UL64*>(hModule) + ntOffset);

      if (!MemLib::MemoryManager::is_valid_memory(ntHeaders))
        return result;

      if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return result;

      const auto exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
      reinterpret_cast<Types::UL64*>(hModule) +
      ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

      if (!MemLib::MemoryManager::is_valid_memory(exportDir))
        return result;

      if (!exportDir)
        return result;

      const auto* names = reinterpret_cast<Types::UL*>(
      reinterpret_cast<Types::UL64*>(hModule) + exportDir->AddressOfNames);

      if (!MemLib::MemoryManager::is_valid_memory(names))
        return result;

      for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
        if (names[i] == 0) continue;

        ExportEntry entry;
        entry.name = reinterpret_cast<const char*>(
            reinterpret_cast<Types::UL64*>(hModule) + names[i]);
        entry.ordinal = *reinterpret_cast<DWORD*>(
            reinterpret_cast<Types::UL64*>(hModule) + exportDir->AddressOfNameOrdinals + (i * sizeof(DWORD)));
        entry.address = *reinterpret_cast<DWORD*>(
            reinterpret_cast<Types::UL64*>(hModule) + exportDir->AddressOfFunctions + (i * sizeof(DWORD)));

        result->push_back(entry);
      }

      return result;
    }

    /**
     * @brief Find all imports from a module
     * @param hModule The modules handle
     * @return A vector of ImportEntry structs pointing to imports
     */
    static std::optional<std::vector<ImportEntry>> parse_import_table(HMODULE hModule) {
      std::optional<std::vector<ImportEntry>> result = std::nullopt;

      if (!hModule) return result;

      const auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
      if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return result;

      const auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
      reinterpret_cast<DWORD_PTR>(hModule) + dosHeader->e_lfanew);

      if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
        return result;

      auto& [VirtualAddress, Size] = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
      if (!VirtualAddress || !Size)
        return result;

      auto* moduleBase = reinterpret_cast<Types::UL64*>(hModule);
      const Types::UL moduleSize = ntHeaders->OptionalHeader.SizeOfImage;
      if (const Types::UL importDirEnd = VirtualAddress + Size; importDirEnd > moduleSize)
        return result;

      result = std::optional<std::vector<ImportEntry>>();
      auto importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(moduleBase + VirtualAddress);
      while (importDesc && importDesc->Name) {
        ImportEntry entry;

        const Types::UL dllNameRVA = importDesc->Name;
        if (dllNameRVA >= moduleSize) break;

        const auto dllNamePtr = reinterpret_cast<const char*>(moduleBase + dllNameRVA);
        if (!dllNamePtr)
          break;

        entry.name = dllNamePtr;

        const Types::UL otfRVA = importDesc->OriginalFirstThunk;
        if (otfRVA >= moduleSize) break;

        const auto originalFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA32>(
        moduleBase + otfRVA);

        if (originalFirstThunk) {
          auto currentRVA = reinterpret_cast<Types::UL64*>(originalFirstThunk);

          while (currentRVA && currentRVA < moduleBase + moduleSize && *reinterpret_cast<Types::UL*>(currentRVA)) {
            if (const Types::UL thunkValue = *reinterpret_cast<Types::UL*>(currentRVA);
                thunkValue & IMAGE_ORDINAL_FLAG64) {
              entry.functions.push_back(std::to_string(thunkValue & 0xFFFF));
            }
            else {
              const Types::UL importByNameRVA = thunkValue;
              if (importByNameRVA >= moduleSize) break;

              const auto importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(moduleBase + importByNameRVA);

              if (importByName && importByName->Name) {
                entry.functions.emplace_back(importByName->Name);
              }
            }

            currentRVA += sizeof(Types::UL);
          }
        }

        result->push_back(entry);
        ++importDesc;
      }

      return result;
    }

    /**
     * @brief Get information about module section headers
     * @param hModule The modules handle
     * @return A vector of SectionHeader structs with each sections information
     */
    static std::vector<SectionHeader> analyze_sections(HMODULE hModule) {
      std::vector<SectionHeader> result = std::vector<SectionHeader>();

      if (!hModule)
        return result;

      const auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
      auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<Types::UL64*>(hModule)
                                                           + dosHeader->e_lfanew);

      auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

      for (Types::US i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        SectionHeader section;
        section.name = std::string(
            reinterpret_cast<const char*>(sectionHeader->Name),
            std::min<size_t>(sizeof(sectionHeader->Name), static_cast<size_t>(8)));
        section.virtual_size = sectionHeader->Misc.VirtualSize;
        section.virtual_address = sectionHeader->VirtualAddress;
        section.size_of_data = sectionHeader->SizeOfRawData;
        section.pointer_to_data = sectionHeader->PointerToRawData;
        section.characteristics = sectionHeader->Characteristics;

        result.push_back(section);
        ++sectionHeader;
      }

      return result;
    }
  };
}
