#pragma once

#include <Windows.h>
#include <vector>
#include <stdexcept>


namespace MemLib {
  /**
   * @brief A helper class to manage aligned memory for SIMD operations
   */
  class MemoryManager {
  private:
    /**
     * @brief A struct holding a pointer to a block of memory
     */
    struct MemoryBlock {
      void* ptr;
      size_t size;
      size_t alignment;
    };

    std::vector<MemoryBlock> blocks_;

  public:
    MemoryManager() = default;

    /**
     * @brief Allocate an aligned block of memory
     * @param size The amount of memory to allocate
     * @param alignment What the block should align to
     * @return A pointer to the allocated memory
     */
    void* allocate(const size_t size, const size_t alignment) {
      void* ptr = _aligned_malloc(size, alignment);
      if (!ptr) throw std::bad_alloc();

      blocks_.push_back({ ptr, size, alignment });
      return ptr;
    }

    /**
     * @brief Free an allocated block of memory
     * @param ptr A pointer to the block of memory
     */
    void free(void* ptr) {
      for (auto it = blocks_.begin(); it != blocks_.end(); ++it) {
        if (it->ptr == ptr) {
          _aligned_free(ptr);
          blocks_.erase(it);
          return;
        }
      }
    }

    /**
     * @brief Check if an address is valid and within valid memory
     * @param ptr A pointer to the block of memory
     * @return A bool; true if valid
     */
    static bool is_valid_memory(const void* ptr) {
      MEMORY_BASIC_INFORMATION mbi;
      return VirtualQuery(ptr, &mbi, sizeof(mbi)) == sizeof(mbi) &&
          mbi.State == MEM_COMMIT &&
          mbi.Protect != PAGE_NOACCESS;
    }
  };

  static auto memoryManager = MemoryManager();
};