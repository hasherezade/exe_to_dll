#include "pe_handler.h"
#include "exports_block.h"

bool PeHandler::isDll()
{
    const IMAGE_FILE_HEADER* hdr = peconv::get_file_hdr(pe_ptr, v_size);
    if (!hdr) return false;
    if (hdr->Characteristics & IMAGE_FILE_DLL) {
        return true;
    }
    return false;
}

bool PeHandler::isConvertable()
{
    if (peconv::has_valid_relocation_table(pe_ptr, v_size)) {
        return true;
    }
    return false;
}

bool PeHandler::setExe()
{
    IMAGE_FILE_HEADER* hdr = const_cast<IMAGE_FILE_HEADER*> (peconv::get_file_hdr(pe_ptr, v_size));
    if (!hdr) return false;

    hdr->Characteristics ^= IMAGE_FILE_DLL;
    return true;
}


inline long long int get_jmp_delta(ULONGLONG currVA, int instrLen, ULONGLONG destVA)
{
    long long int diff = destVA - (currVA + instrLen);
    return diff;
}

bool PeHandler::exeToDllPatch()
{
    BYTE back_stub32[] = {
        0xB8, 0x01, 0x00, 0x00, 0x00, //MOV EAX, 1
        0xC2, 0x0C, 0x00 //retn 0x0C
    };

    BYTE back_stub64[] = {
        0xB8, 0x01, 0x00, 0x00, 0x00, //MOV EAX, 1
        0xC3
    };

    BYTE *back_stub = back_stub32;
    size_t stub_size = sizeof(back_stub32);
    if (is64bit) {
        back_stub = back_stub64;
        stub_size = sizeof(back_stub64);
    }
    size_t call_offset = stub_size - 6;

    BYTE* ptr = peconv::find_padding_cave(pe_ptr, v_size, stub_size, IMAGE_SCN_MEM_EXECUTE);
    if (!ptr) {
        return false;
    }
    memmove(ptr, back_stub, stub_size);
    DWORD new_ep = DWORD(ptr - this->pe_ptr);
    return peconv::update_entry_point_rva(this->pe_ptr, new_ep);
}

bool PeHandler::savePe(const char *out_path)
{
    std::string path = out_path;
    std::string dllname = path.substr(path.find_last_of("/\\") + 1);

    ExportsBlock exp(this->ep, dllname.c_str(), "Start");
    if (!exp.appendToPE(pe_ptr)) {
        std::cerr << "[!] Failed to create an Export Directory!\n";
    }
    size_t out_size = 0;
    /*in this case we need to use the original module base, because
    * the loaded PE was not relocated */
    ULONGLONG module_base = peconv::get_image_base(pe_ptr);

    BYTE* unmapped_module = peconv::pe_virtual_to_raw(pe_ptr,
        v_size,
        module_base, //the original module base
        out_size // OUT: size of the unmapped (raw) PE
    );
    bool is_ok = false;
    if (unmapped_module) {
        if (peconv::dump_to_file(out_path, unmapped_module, out_size)) {
            is_ok = true;
        }
        peconv::free_pe_buffer(unmapped_module, v_size);
    }
    return is_ok;
}
