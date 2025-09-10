#pragma once

#include <peconv.h>

class PeHandler
{
public:
    PeHandler(const char *path)
    {
        size_t orig_vsize = 0;
        BYTE *orig_pe = peconv::load_pe_module(path, orig_vsize, false, false);
        if (!orig_pe) return;

        const size_t padded_size = orig_vsize + PAGE_SIZE;
        this->pe_ptr = (BYTE*)peconv::alloc_aligned(padded_size, PAGE_READWRITE);
        if (this->pe_ptr) {
            ::memcpy(this->pe_ptr, orig_pe, orig_vsize);
            this->v_size = padded_size;
        }
        peconv::free_pe_buffer(orig_pe);
        if (!this->pe_ptr) {
            return;
        }
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
    bool appendExportsTable(std::string dllname);

    bool savePe(const char *path);
protected:

    size_t v_size;
    BYTE *pe_ptr;

    bool is64bit;
    DWORD ep;

};
