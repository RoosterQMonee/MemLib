#pragma once

#include <cstdint>

namespace MemLib {
    template <typename R, typename... Args>
    static inline R call_func(void* func, Args... args) {
        return ((R(*)(Args...))func)(args...);
    }

    template <unsigned int IIdx, typename Ret, typename... Args>
    static inline auto call_vfunc(void* thisptr, Args... argList) -> Ret {
        using Fn = Ret(__thiscall*)(void*, decltype(argList)...);
        return (*static_cast<Fn**>(thisptr))[IIdx](thisptr, argList...);
    }

    template <typename Ret, typename... Args>
    static auto call_vfunc_index(uint32_t index, void* thisptr, Args... argList) -> Ret {
        using Fn = Ret(__thiscall*)(void*, Args...);
        return (*static_cast<Fn**>(thisptr))[index](thisptr, std::forward<Args>(argList)...);
    }

    template <typename Ret, typename... Args>
    static inline auto* get_fastcall(void* Original) {
        using Fn = Ret(__fastcall*)(Args...);
        return reinterpret_cast<Fn>(Original);
    }

    template <typename Ret, typename Type>
    static Ret& direct_access(Type* type, size_t offset) {
        union {
            size_t raw;
            Type* source;
            Ret* target;
        } u;

        u.source = type;
        u.raw += offset;

        return *u.target;
    }

    template<typename Ret, typename Type>
    auto& member_at(Type* ptr, int offset) {
        return *reinterpret_cast<Ret*>(reinterpret_cast<std::uintptr_t>(ptr) + offset);
    }
};