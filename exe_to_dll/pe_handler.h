#pragma once

#include <peconv.h>

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
