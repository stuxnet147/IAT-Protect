void memcpy_(void* _DesPIntArr, const void* _NowPIntArr, const int size)
{
    char* desArr = (char*)_DesPIntArr;
    char* nowArr = (char*)_NowPIntArr;

    for (int i = 0; i < size; ++i)
    {
        desArr[i] = nowArr[i];
    }
}

auto get_iat()
{
    std::vector<__int64> iat;

    LPVOID imageBase = GetModuleHandleA(NULL);

    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + (DWORD_PTR)imageBase);

    while (importDescriptor->Name != NULL)
    {
        HMODULE library = library = LoadLibraryA((LPCSTR)importDescriptor->Name + (DWORD_PTR)imageBase);

        if (library)
        {
            PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
            PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk);

            while (originalFirstThunk->u1.AddressOfData != NULL)
            {
                SIZE_T bytesWritten = 0;
                DWORD oldProtect = 0;

                if (((__int64*)(firstThunk->u1.Function) < (__int64*)0x7FFFFFEEFFFE) == true)
                    if (VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect))
                        iat.push_back((__int64)&firstThunk->u1.Function);

                ++originalFirstThunk;
                ++firstThunk;
            }
        }

        importDescriptor++;
    }

    return iat;
}

auto DumpGuard()
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned __int64> random(0, 0x7FFFFFFF);
    std::stack<std::pair<int, __int64>> inst;

    BYTE shellcode[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    BYTE tmp_shellcode1[] = { 0x48, 0x2D, 0x00, 0x00, 0x00, 0x00 };
    BYTE tmp_shellcode2[] = { 0x48, 0x05, 0x00, 0x00, 0x00, 0x00 };
    BYTE tmp_shellcode3[] = { 0x48, 0x35, 0x00, 0x00, 0x00, 0x00 };

    auto buffer0 = (__int64)VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    auto buffer1 = (__int64)VirtualAlloc(0, sizeof(tmp_shellcode1), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    auto buffer2 = (__int64)VirtualAlloc(0, sizeof(tmp_shellcode2), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    auto buffer3 = (__int64)VirtualAlloc(0, sizeof(tmp_shellcode3), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    memcpy_((LPVOID)buffer0, shellcode, sizeof(shellcode));
    memcpy_((LPVOID)buffer1, tmp_shellcode1, sizeof(tmp_shellcode1));
    memcpy_((LPVOID)buffer2, tmp_shellcode2, sizeof(tmp_shellcode2));
    memcpy_((LPVOID)buffer3, tmp_shellcode3, sizeof(tmp_shellcode3));

    for (auto&& v : get_iat())
    {
        __int64 address = *(__int64*)v;
        int max_round = 8;

        auto round = std::min((int)(random(gen) % max_round), 46);

        for (int i = 0; i < round; i++)
        {
            auto use_inst = random(gen) % 3;
            switch (use_inst)
            {
            case 0://sub
            {
                auto tmp = random(gen) & 0x00000000FFFFFFFF;
                inst.push(std::make_pair(use_inst, tmp));
                address -= tmp;
                break;
            }
            case 1://add
            {
                auto tmp = random(gen) & 0x00000000FFFFFFFF;
                inst.push(std::make_pair(use_inst, tmp));
                address += tmp;
                break;
            }
            case 2://xor
            {
                auto tmp = random(gen);
                inst.push(std::make_pair(use_inst, tmp));
                address ^= tmp;
                break;
            }
            default:
                break;
            }
        }

        auto backup = address;
        auto buffer_ = VirtualAlloc(0, 0x3000, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
        auto buffer = buffer_;
        *(__int64*)(buffer0 + 2) = address;

        memcpy_(buffer, (LPVOID)buffer0, 0xA);
        buffer = (LPVOID)((__int64)buffer + 0xA);

        for (int i = 0; i < round; i++)
        {
            auto instruction = inst.top();
            switch (instruction.first)
            {
            case 0://sub
            {
                *(__int64*)(buffer2 + 2) = instruction.second;
                backup += instruction.second;
                memcpy_(buffer, (LPVOID)buffer2, 6);
                buffer = (LPVOID)((__int64)buffer + 6);
                break;
            }
            case 1://add
            {
                *(__int64*)(buffer1 + 2) = instruction.second;
                backup -= instruction.second;
                memcpy_(buffer, (LPVOID)buffer1, 6);
                buffer = (LPVOID)((__int64)buffer + 6);
                break;
            }
            case 2://xor
            {
                *(__int64*)(buffer3 + 2) = instruction.second;
                backup ^= instruction.second;
                memcpy_(buffer, (LPVOID)buffer3, 6);
                buffer = (LPVOID)((__int64)buffer + 6);
                break;
            }
            default:
                break;
            }
            inst.pop();
        }

        BYTE exit_[2] = { 0xFF, 0xE0 };
        memcpy_(buffer, (LPVOID)exit_, 2);
        *(__int64*)v = (__int64)buffer_;
    }
}
