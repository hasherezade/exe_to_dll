#pragma once

#include <peconv.h>
#include "pe_handler.h"

#include <string>

struct ExportedFunc
{
    DWORD funcRva;
    WORD ord;
    std::string funcName;

    ExportedFunc(DWORD _funcRva, WORD _ord, const std::string& _funcName) :
        funcRva(_funcRva), ord(_ord), funcName(_funcName)
    {
    }
};

class ExportsBlock
{
public:
    ExportsBlock()
        : buf(nullptr), size(0), reloc_base(0)
    {
    }

    ~ExportsBlock()
    {
        release();
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
        BYTE* exp_ptr = nullptr;

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

        if (exp_ptr) {
            BYTE* table_va = exp_ptr + pad;
            if (appendAtVA(pe_module, v_size, (ULONG_PTR)table_va)) {
                expDone = true;
            }
        }
        return expDone;
    }

    bool createBlock(const std::string& dll_name, const std::vector<ExportedFunc>& functions, const DWORD ordBase = 1)
    {
        this->release();

        const char* dllName = dll_name.c_str();
        const size_t funcs_count = functions.size();
        size_t export_area_size = calculateSize(funcs_count, dllName, functions);
        BYTE* exports_area = (BYTE*)calloc(1, export_area_size);
        IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)exports_area;
        ULONG_PTR last_ptr = (ULONG_PTR)exports_area + sizeof(IMAGE_EXPORT_DIRECTORY);
        if (!exp) {
            return false;
        }
        exp->NumberOfFunctions = funcs_count;
        exp->NumberOfNames = 0;
        exp->Base = ordBase;
        exp->TimeDateStamp = (-1);

        DWORD* addresses = (DWORD*)last_ptr;
        exp->AddressOfFunctions = DWORD((ULONG_PTR)addresses - (ULONG_PTR)exports_area);
        last_ptr += (funcs_count + 1) * sizeof(DWORD);

        DWORD* name_addr = (DWORD*)last_ptr;
        exp->AddressOfNames = DWORD((ULONG_PTR)name_addr - (ULONG_PTR)exports_area);
        last_ptr += (funcs_count + 1) * sizeof(DWORD);

        WORD* name_ords = (WORD*)last_ptr;
        exp->AddressOfNameOrdinals = WORD((ULONG_PTR)name_ords - (ULONG_PTR)exports_area);
        last_ptr += (funcs_count + 1) * sizeof(WORD);

        char* names = (char*)last_ptr;

        for (size_t func_count = 0; func_count < functions.size(); ++func_count) {
            ExportedFunc func = functions[func_count];
            const size_t nameLen = func.funcName.length();
            if (nameLen) {
                ::memcpy(names, func.funcName.c_str(), nameLen);
                const DWORD rva = DWORD((ULONG_PTR)names - (ULONG_PTR)exports_area);
                last_ptr += (nameLen + 1);
                names = (char*)last_ptr;
                name_addr[exp->NumberOfNames] = rva;
                name_ords[exp->NumberOfNames] = func_count;
                exp->NumberOfNames++;
            }
            addresses[func_count] = func.funcRva;
        }

        char* dll_name_ptr = (char*)last_ptr;
        ::memcpy(dll_name_ptr, dllName, strlen(dllName));
        exp->Name = ((ULONG_PTR)dll_name_ptr - (ULONG_PTR)exports_area);

        this->size = export_area_size;
        this->buf = exports_area;
        return true;
    }

    BYTE* buf;
    size_t size;

protected:
    
    void release()
    {
        if (this->buf) {
            ::free(buf);
        }
        this->buf = nullptr;
        this->size = 0;
    }

    size_t calculateSize(DWORD funcs_count, const char* dllName, const std::vector<ExportedFunc>& functions)
    {
        size_t func_names_size = strlen(dllName) + 1;
        for (auto itr = functions.begin(); itr != functions.end(); ++itr) {
            const std::string &name = itr->funcName;
            func_names_size += name.length() + 1;
        }
        size_t funcs_size = (sizeof(DWORD) * 2 + sizeof(WORD)) * (funcs_count + 1) + func_names_size;
        size_t export_area_size = sizeof(IMAGE_EXPORT_DIRECTORY) + funcs_size;
        return export_area_size;
    }

    size_t reloc_base;
};
