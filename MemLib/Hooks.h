#pragma once

#include <Windows.h>
#include <vector>
#include <memory>
#include <unordered_map>
#include <string>
#include <stdexcept>

#include "MinHook/Minhook.h"
#include "Scanner.h"


#ifndef NO_THROW_EXCEPTIONS
#define __ML_THROW_EXCEPTION(ex) throw std::runtime_error(ex);
#else
#define __ML_THROW_EXCEPTION(ex) return;
#endif


namespace MemLib {
	enum HookType {
		Signature,     // Signature dependent
		DirectAddress, // Pointer to function
		Independent    // Other method
	};

	class HookBase {
	public:
		HookBase() {};
		~HookBase() {};

		virtual void Enable(const void* base, size_t module_length) {};
		virtual void Disable() {};

        bool isEnabled{};
	};

    template <HookType T>
    class Hook : public HookBase {
    public:
        void* originalFunction{};

        Hook(char* name, char* pattern, PDWORD address, void* hookFunction)
            : hookType(T), _pattern(pattern), _address(reinterpret_cast<void*>(address)),
            hookedFunction(hookFunction), _name(name) {
            printf("[%s] Created Hook\n", _name);
        }

        virtual ~Hook() { this->Disable(); }

        virtual void Enable(const void* base, size_t module_length) override {
            if (T == HookType::Independent) {
                printf("[%s] Independent function missing Enable()!\n", _name);
                return;
            }

            void* targetAddress = _address;
            std::optional<MemLib::ScanResult> result{};

            if (T == HookType::Signature) {
                std::optional<MemLib::ScanResult> scan = MemLib::scanner.scan_pattern(_pattern, base, module_length);
                if (!scan.has_value()) {
                    printf("[%s] Failed to scan!\n", _name);
                    return;
                } else if (scan.value().address == 0) {
                    printf("[%s] Couldn't find signature!\n", _name);
                    return;
                }
                targetAddress = scan.value().address;
            }

            MH_STATUS ret = MH_CreateHook(targetAddress, hookedFunction, &originalFunction);
            if (ret != MH_OK) {
                printf("[%s] Failed to create hook! (%d)\n", _name, ret);
                return;
            }

            ret = MH_EnableHook(targetAddress);
            if (ret != MH_OK) {
                printf("[%s] Failed to enable hook! (%d)\n", _name, ret);
                return;
            }

            this->isEnabled = true;
        }

        virtual void Disable() override {
            if (!this->isEnabled)
                return;

            MH_DisableHook(originalFunction);
            MH_RemoveHook(originalFunction);

            originalFunction = nullptr;
            hookedFunction = nullptr;
            isEnabled = false;
        }

    private:
        void* hookedFunction{};
        char* _pattern{};
        char* _name{};
        void* _address{};

        HookType hookType{};
    };


	class HookManager {
	public:
		template <HookType T>
		std::shared_ptr<Hook<T>> AddHook(const char* name, PDWORD address = 0, void* hookedFunc = nullptr) {
            auto hook = std::make_shared<Hook<T>>(
                const_cast<char*>(name),
                (char*)"",
                address,
                hookedFunc);
            hooks_.push_back(hook);
            return hook;
		}

        template <HookType T>
        std::shared_ptr<Hook<T>> AddHook(const char* name, char* pattern = "", void* hookedFunc = nullptr) {
            auto hook = std::make_shared<Hook<T>>(
                const_cast<char*>(name),
                pattern,
                (PDWORD)0,
                hookedFunc);
            hooks_.push_back(hook);
            return hook;
        }

        template <HookType T>
        std::shared_ptr<Hook<T>> AddHook(const char* name, const char* pattern = "", void* hookedFunc = nullptr) {
            auto hook = std::make_shared<Hook<T>>(
                const_cast<char*>(name),
                const_cast<char*>(pattern),
                (PDWORD)0,
                hookedFunc);
            hooks_.push_back(hook);
            return hook;
        }

        template <HookType T>
        std::shared_ptr<Hook<T>> AddHook(const char* name, void* hookedFunc = nullptr) {
            auto hook = std::make_shared<Hook<T>>(
                const_cast<char*>(name),
                const_cast<char*>(""),
                (PDWORD)0,
                hookedFunc);
            hooks_.push_back(hook);
            return hook;
        }

		bool RemoveHook(const std::shared_ptr<HookBase>& hook) {
			auto it = std::find_if(hooks_.begin(), hooks_.end(),
				[&hook](const auto& h) { return h.get() == hook.get(); });
			if (it != hooks_.end()) {
				hooks_.erase(it);
				return true;
			}
			return false;
		}

        void Init() {
            MH_Initialize();
        }

		void Clear() {
			hooks_.clear();
		}

		size_t Size() const {
			return hooks_.size();
		}

		const std::vector<std::shared_ptr<HookBase>>& GetAllHooks() const {
			return hooks_;
		}

		void EnableAll(const void* base, size_t module_length) {
			for (const auto& hook : hooks_)
				if (!hook->isEnabled)
					hook->Enable(base, module_length);
		}

		void DisableAll() {
			for (const auto& hook : hooks_)
				hook->Disable();
		}

	private:
		std::vector<std::shared_ptr<HookBase>> hooks_ = std::vector<std::shared_ptr<HookBase>>();
	};

    using SignatureHook = Hook<MemLib::HookType::Signature>;
    using DirectHook = Hook<MemLib::HookType::DirectAddress>;
    using IndependentHook = Hook<MemLib::HookType::Independent>;
}