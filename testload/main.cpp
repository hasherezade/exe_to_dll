#include <windows.h>
#include <iostream>

#include <peconv.h>

int main(int argc, char *argv[])
{
    if (argc < 3) {
        std::cout << "~ testload ~\n"
            << "Try to load DLL file.\n";
#ifdef _WIN64
        std::cout << "For 64-bit DLLs.\n";
#else
        std::cout << "For 32-bit DLLs.\n";
#endif
        std::cout << "Args: <dll> <Entry Point RVA>\n"
            << "<dll>: the DLL converted by dll_to_exe\n" 
            << "<Entry Point RVA>: the Original Entry Point of your application (before the conversion to DLL)"<< std::endl;
        system("pause");
        return 0;
    }

    char* in_path = argv[1];

    ULONGLONG ep_rva = 0;
    if (sscanf(argv[2], "%llX", &ep_rva) == 0) {
        sscanf(argv[2], "%#llX", &ep_rva);
    }
    if (!ep_rva) {
        std::cerr << "[!] Cannot parse the Entry Point\n";
        return -2;
    }

    HMODULE hTargetDll = LoadLibraryA(in_path);
    if (!hTargetDll)
    {
        std::cerr << "[!] LoadLibraryA failed. Error: " << GetLastError() << std::endl;
        return -1;
    }

    printf("[+] Target DLL base address: 0x%p\n", hTargetDll);

    ULONG_PTR ep_va = ep_rva + (ULONG_PTR)hTargetDll;
    std::cout << "[*] Calling EP at: " << std::hex << ep_va << std::endl;

    // assuming that the given function follows the simplest prototype of main:
    int(*new_main)() = (int(*)())ep_va;

    //call the Entry Point of the manually loaded PE:
    return new_main();
}
