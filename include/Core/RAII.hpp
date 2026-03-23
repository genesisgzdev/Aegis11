#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <utility>

namespace Aegis::Core {

    template <typename Traits>
    class UniqueHandle {
        using pointer = typename Traits::pointer;
        pointer m_handle;

        explicit UniqueHandle(pointer h) noexcept : m_handle(h) {}

        void close() noexcept {
            if (*this) {
                Traits::close(m_handle);
#ifdef _DEBUG
                m_handle = reinterpret_cast<pointer>(0xDEADBEEF);
#else
                m_handle = Traits::invalid();
#endif
            }
        }

    public:
        UniqueHandle() noexcept : m_handle(Traits::invalid()) {}
        ~UniqueHandle() noexcept { close(); }

        static UniqueHandle From(pointer h) noexcept { return UniqueHandle(h); }

        UniqueHandle(const UniqueHandle&) = delete;
        UniqueHandle& operator=(const UniqueHandle&) = delete;

        UniqueHandle(UniqueHandle&& other) noexcept : m_handle(other.release()) {}
        UniqueHandle& operator=(UniqueHandle&& other) noexcept {
            if (this != &other) reset(other.release());
            return *this;
        }

        [[nodiscard]] explicit operator bool() const noexcept { 
            return m_handle != Traits::invalid() && m_handle != reinterpret_cast<pointer>(0xDEADBEEF); 
        }
        
        [[nodiscard]] pointer get() const noexcept { return m_handle; }
        
        [[nodiscard]] pointer* put() noexcept {
            reset();
            return &m_handle;
        }

        [[nodiscard]] pointer release() noexcept {
            pointer temp = m_handle;
#ifdef _DEBUG
            m_handle = reinterpret_cast<pointer>(0xDEADBEEF);
#else
            m_handle = Traits::invalid();
#endif
            return temp;
        }

        void reset(pointer h = Traits::invalid()) noexcept {
            if (m_handle != h) {
                close();
                m_handle = h;
            }
        }

        void swap(UniqueHandle& other) noexcept {
            std::swap(m_handle, other.m_handle);
        }

        bool operator==(const UniqueHandle& other) const noexcept { return m_handle == other.m_handle; }
        bool operator!=(const UniqueHandle& other) const noexcept { return !(*this == other); }
    };

    struct HandleTraits {
        using pointer = HANDLE;
        static pointer invalid() noexcept { return nullptr; }
        static void close(pointer h) noexcept { if (h) CloseHandle(h); }
    };

    struct FileHandleTraits {
        using pointer = HANDLE;
        static pointer invalid() noexcept { return INVALID_HANDLE_VALUE; }
        static void close(pointer h) noexcept { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    };

    struct RegTraits {
        using pointer = HKEY;
        static pointer invalid() noexcept { return nullptr; }
        static void close(pointer h) noexcept { if (h) RegCloseKey(h); }
    };

    struct SvcTraits {
        using pointer = SC_HANDLE;
        static pointer invalid() noexcept { return nullptr; }
        static void close(pointer h) noexcept { if (h) CloseServiceHandle(h); }
    };

    struct ModuleTraits {
        using pointer = HMODULE;
        static pointer invalid() noexcept { return nullptr; }
        static void close(pointer h) noexcept { if (h) FreeLibrary(h); }
    };

    using KernelHandle = UniqueHandle<HandleTraits>;
    using FileHandle = UniqueHandle<FileHandleTraits>;
    using RegHandle = UniqueHandle<RegTraits>;
    using SvcHandle = UniqueHandle<SvcTraits>;
    using ModuleHandle = UniqueHandle<ModuleTraits>;

    template <typename T>
    class ComPtr {
        T* m_ptr;
        void InternalAddRef() const noexcept { if (m_ptr) m_ptr->AddRef(); }
        void InternalRelease() noexcept { if (m_ptr) { m_ptr->Release(); m_ptr = nullptr; } }
        explicit ComPtr(T* lp, bool addRef) noexcept : m_ptr(lp) { if (addRef) InternalAddRef(); }

    public:
        ComPtr() noexcept : m_ptr(nullptr) {}
        ComPtr(std::nullptr_t) noexcept : m_ptr(nullptr) {}
        ~ComPtr() noexcept { InternalRelease(); }

        static ComPtr<T> Adopt(T* lp) noexcept { return ComPtr<T>(lp, false); }
        static ComPtr<T> Copy(T* lp) noexcept { return ComPtr<T>(lp, true); }

        ComPtr(const ComPtr& other) noexcept : m_ptr(other.m_ptr) { InternalAddRef(); }
        ComPtr& operator=(const ComPtr& other) noexcept {
            if (this != &other) { InternalRelease(); m_ptr = other.m_ptr; InternalAddRef(); }
            return *this;
        }

        ComPtr(ComPtr&& other) noexcept : m_ptr(other.m_ptr) { other.m_ptr = nullptr; }
        ComPtr& operator=(ComPtr&& other) noexcept {
            if (this != &other) { InternalRelease(); m_ptr = other.m_ptr; other.m_ptr = nullptr; }
            return *this;
        }

        [[nodiscard]] T* get() const noexcept { return m_ptr; }
        [[nodiscard]] T* operator->() const noexcept { return m_ptr; }
        [[nodiscard]] T& operator*() const noexcept { return *m_ptr; }
        [[nodiscard]] explicit operator bool() const noexcept { return m_ptr != nullptr; }

        T** operator&() = delete; 
        
        [[nodiscard]] T** ReleaseAndGetAddressOf() noexcept { InternalRelease(); return &m_ptr; }

        void Attach(T* lp) noexcept { InternalRelease(); m_ptr = lp; }
        [[nodiscard]] T* Detach() noexcept { T* temp = m_ptr; m_ptr = nullptr; return temp; }
        void Reset() noexcept { InternalRelease(); }

        template <typename U>
        [[nodiscard]] ComPtr<U> As() const noexcept {
            ComPtr<U> p;
            if (m_ptr) {
                m_ptr->QueryInterface(__uuidof(U), reinterpret_cast<void**>(p.ReleaseAndGetAddressOf()));
            }
            return p;
        }

        void swap(ComPtr& other) noexcept { std::swap(m_ptr, other.m_ptr); }

        bool operator==(const ComPtr& other) const noexcept { return m_ptr == other.m_ptr; }
        bool operator==(T* other) const noexcept { return m_ptr == other; } 
        bool operator!=(const ComPtr& other) const noexcept { return m_ptr != other.m_ptr; }
        bool operator!=(T* other) const noexcept { return m_ptr != other; }
    };
}
