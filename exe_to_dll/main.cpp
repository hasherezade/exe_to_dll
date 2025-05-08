#include <stdio.h>
#include <windows.h>

#include <peconv.h>
#include "pe_handler.h"

#define VERSION "1.2"

int main(int argc, char *argv[])
{
    if (argc < 3) {
        std::cout << "EXE to DLL converter v"<< VERSION << " \n- for 32 & 64 bit DLLs -" << std::endl;
        std::cout << "args: <input_exe> <output_dll>" << std::endl;
        system("pause");
        return 0;
    }
    char *filename = argv[1];
    char *outfile = argv[2];

    PeHandler hndl(filename);
    if (hndl.isDll()) {
        std::cout << "It is already a DLL!" << std::endl;
        return 0;
    }
    if (!hndl.isConvertable()) {
        std::cerr << "[!] This EXE is not suitable for conversion: relocation table missing or invalid!" << std::endl;
        return -1;
    }
    hndl.setExe();
    if (!hndl.exeToDllPatch()) {
        std::cerr << "[!] Could not convert!" << std::endl;
        return -1;
    }
    std::cout << "[OK] Converted successfuly." << std::endl;
    if (hndl.savePe(outfile)) {
        std::cout << "[OK] Module dumped to: " << outfile << std::endl;
    }
    return 0;
}
