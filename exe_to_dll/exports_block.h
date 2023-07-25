#pragma once

#include <peconv.h>
#include "pe_handler.h"

class ExportsBlock
{
public:
    ExportsBlock(DWORD func_rva, const char* dllName, const char* funcName)
        : buf(nullptr), size(0), reloc_base(0)
    {
        createBlock(func_rva, dllName, funcName);
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
            name_addr[i] -= reloc_base;
            name_addr[i] += table_rva;
        }

        exp->AddressOfFunctions -= reloc_base;
        exp->AddressOfFunctions += table_rva;

        exp->AddressOfNameOrdinals -= reloc_base;
        exp->AddressOfNameOrdinals += table_rva;

        exp->AddressOfNames -= reloc_base;
        exp->AddressOfNames += table_rva;

        exp->Name -= reloc_base;
        exp->Name += table_rva;
        
        this->reloc_base = table_rva;
        return true;
    }

    bool appendAtVA(BYTE* pe_module, size_t pe_vsize, ULONG_PTR table_va)
    {
        if (!pe_module) return false;

        IMAGE_DATA_DIRECTORY* dir = peconv::get_directory_entry(pe_module, IMAGE_DIRECTORY_ENTRY_EXPORT, true);
        if (!dir) return false;

        DWORD table_rva = table_va - (ULONG_PTR)pe_module;
        if (!peconv::validate_ptr(pe_module, pe_vsize, (BYTE*)table_va, size)) {
            std::cerr << "[!] No space to append the table! Needed size: " << std::hex << size << "\n";
            return false;
        }
        relocateToRva(table_rva);
        ::memcpy((BYTE*)table_va, buf, size);

        dir->Size = size;
        dir->VirtualAddress = table_rva;
        return true;
    }

    bool appendToPE(BYTE* pe_module)
    {
        if (!pe_module) return false;

        size_t v_size = peconv::get_image_size(pe_module);
        if (!v_size) return false;

        bool expDone = false;
        const size_t pad = 2;
        const size_t needed_size = this->size + pad;
        BYTE* exp_ptr = peconv::find_padding_cave(pe_module, v_size, needed_size, IMAGE_SCN_MEM_READ);
        if (!exp_ptr) {
            PIMAGE_SECTION_HEADER hdr = peconv::get_last_section(pe_module, v_size, true);
            if (hdr && hdr->PointerToRawData) {
                size_t bigger_size = (hdr->SizeOfRawData > hdr->Misc.VirtualSize) ? hdr->SizeOfRawData : hdr->Misc.VirtualSize;
                ULONG_PTR raw_end = hdr->PointerToRawData + bigger_size;
                if (v_size > raw_end) {
                    DWORD diff = v_size - raw_end;
                    if (diff >= needed_size) {
                        exp_ptr = pe_module + hdr->VirtualAddress + bigger_size;
                        hdr->SizeOfRawData = hdr->Misc.VirtualSize = bigger_size + needed_size;
                        hdr->Characteristics |= IMAGE_SCN_MEM_READ; //ensure that the section is readable
                    }
                }
            }
        }
        if (exp_ptr) {
            BYTE* table_va = exp_ptr + pad;
            if (appendAtVA(pe_module, v_size, (ULONG_PTR)table_va)) {
                expDone = true;
            }
        }
        return expDone;
    }

    BYTE* buf;
    size_t size;

protected:
    size_t calculateSize(DWORD funcs_count, const char* dllName, const char* funcName)
    {
        size_t func_names_size = strlen(funcName) + 1 + strlen(dllName) + 1;
        size_t funcs_size = (sizeof(DWORD) * 2 + sizeof(WORD)) * (funcs_count + 1) + func_names_size;
        size_t export_area_size = sizeof(IMAGE_EXPORT_DIRECTORY) + funcs_size;
        return export_area_size;
    }

    bool createBlock(DWORD func_rva, const char* dllName, const char* funcName)
    {
        size_t funcs_count = 1;
        size_t export_area_size = calculateSize(funcs_count, dllName, funcName);
        BYTE* exports_area = (BYTE*)calloc(1, export_area_size);
        IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)exports_area;
        ULONG_PTR last_ptr = (ULONG_PTR)exports_area + sizeof(IMAGE_EXPORT_DIRECTORY);
        if (!exp) return false;

        exp->NumberOfFunctions = funcs_count;
        exp->NumberOfNames = funcs_count;
        exp->Base = 1;

        DWORD* addresses = (DWORD*)last_ptr;
        addresses[0] = func_rva;
        exp->AddressOfFunctions = ((ULONG_PTR)addresses - (ULONG_PTR)exports_area);

        last_ptr += (funcs_count + 1) * sizeof(DWORD);
        DWORD* name_addr = (DWORD*)last_ptr;
        exp->AddressOfNames = ((ULONG_PTR)name_addr - (ULONG_PTR)exports_area);

        last_ptr += (funcs_count + 1) * sizeof(DWORD);
        WORD* ordinals = (WORD*)last_ptr;
        exp->AddressOfNameOrdinals = ((ULONG_PTR)ordinals - (ULONG_PTR)exports_area);

        last_ptr += (funcs_count + 1) * sizeof(WORD);
        char* names = (char*)last_ptr;
        ::memcpy(names, funcName, strlen(funcName));
        last_ptr += strlen(funcName) + 1;

        DWORD names_rva = ((ULONG_PTR)names - (ULONG_PTR)exports_area);
        name_addr[0] = names_rva;

        char* dll_name_ptr = (char*)last_ptr;
        ::memcpy(dll_name_ptr, dllName, strlen(dllName));
        exp->Name = ((ULONG_PTR)dll_name_ptr - (ULONG_PTR)exports_area);

        this->size = export_area_size;
        this->buf = exports_area;
        return true;
    }

    size_t reloc_base;
};
