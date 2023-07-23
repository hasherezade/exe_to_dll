#pragma once

#include "peconv.h"


class ExportsBlock
{
public:
    ExportsBlock(DWORD func_rva, char* name)
        : buf(nullptr), size(0)
    {
        createBlock(func_rva, name);
    }

    ~ExportsBlock()
    {
        ::free(buf);
        buf = nullptr;
        size = 0;
    }

    bool relocateToRva(DWORD table_rva)
    {
        if (!buf) return false;

        IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)buf;
        DWORD* name_addr = (DWORD*)((ULONG_PTR)buf + exp->AddressOfNames);
        for (size_t i = 0; i < exp->NumberOfNames; i++) {
            name_addr[i] += table_rva;
        }

        exp->AddressOfFunctions += table_rva;
        exp->AddressOfNameOrdinals += table_rva;
        exp->AddressOfNames += table_rva;
        return true;
    }

    bool appendToPE(BYTE *pe_module, ULONG_PTR table_va)
    {
        IMAGE_DATA_DIRECTORY* dir = peconv::get_directory_entry(pe_module, 0, true);
        if (!dir) return false;

        DWORD table_rva = table_va - (ULONG_PTR)pe_module;
        relocateToRva(table_rva);
        ::memcpy((BYTE*)table_va, buf, size);

        dir->Size = size;
        dir->VirtualAddress = table_rva;
        return true;
    }

    BYTE* buf;
    size_t size;

protected:
    size_t calculateSize(DWORD funcs_count, char* func_name)
    {
        size_t func_names_size = strlen(func_name) + 1;
        size_t funcs_size = (sizeof(DWORD) * 2 + sizeof(WORD)) * (funcs_count + 1) + func_names_size;
        size_t export_area_size = sizeof(IMAGE_EXPORT_DIRECTORY) + funcs_size;
        return export_area_size;
    }

    bool createBlock(DWORD func_rva, char* func_name)
    {
        size_t funcs_count = 1;
        size_t export_area_size = calculateSize(funcs_count, func_name);
        BYTE* exports_area = (BYTE*)calloc(1, export_area_size);
        IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)exports_area;
        if (!exp) return false;

        exp->NumberOfFunctions = funcs_count;
        exp->NumberOfNames = funcs_count;
        exp->Base = 1;

        DWORD* addesses = (DWORD*)((ULONG_PTR)exports_area + sizeof(IMAGE_EXPORT_DIRECTORY));
        addesses[0] = func_rva;
        exp->AddressOfFunctions = ((ULONG_PTR)addesses - (ULONG_PTR)exports_area);

        DWORD* name_addr = (DWORD*)((ULONG_PTR)exports_area + sizeof(IMAGE_EXPORT_DIRECTORY) + (funcs_count + 1) * sizeof(DWORD));
        exp->AddressOfNames = ((ULONG_PTR)name_addr - (ULONG_PTR)exports_area);

        WORD* ordinals = (WORD*)((ULONG_PTR)exports_area + sizeof(IMAGE_EXPORT_DIRECTORY) + (funcs_count + 1) * sizeof(DWORD) * 2);
        exp->AddressOfNameOrdinals = ((ULONG_PTR)ordinals - (ULONG_PTR)exports_area);

        char* names = (char*)((ULONG_PTR)exports_area + sizeof(IMAGE_EXPORT_DIRECTORY) + (funcs_count + 1) * (sizeof(DWORD) * 2 + sizeof(WORD)));
        ::memcpy(names, func_name, strlen(func_name));

        DWORD names_rva = ((ULONG_PTR)names - (ULONG_PTR)exports_area);
        name_addr[0] = names_rva;

        this->size = export_area_size;
        this->buf = exports_area;
        return true;
    }

};

class PeHandler
{
public:
    PeHandler(const char *path)
    {
        pe_ptr = peconv::load_pe_module(path, v_size, false, false);
        if (!pe_ptr) return;

        ep = peconv::get_entry_point_rva(pe_ptr);
        is64bit = peconv::is64bit(pe_ptr);
    }

    ~PeHandler()
    {
        peconv::free_pe_buffer(pe_ptr);
    }

    bool is64()
    {
        return is64bit;
    }

    bool isDll();

    bool isConvertable();

    bool setExe();

    bool exeToDllPatch();
    bool savePe(const char *path);

protected:

    size_t v_size;
    BYTE *pe_ptr;

    bool is64bit;
    DWORD ep;
};
