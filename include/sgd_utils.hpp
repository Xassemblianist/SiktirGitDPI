#pragma once
#include <cstdio>
#include <cctype>
#include <string>

namespace SGDPI {
    namespace Utils {
        void HexDump(void* ptr, int buflen);
        void ParseArguments(int argc, char** argv);
        std::string GetTimestamp();
        bool IsAdmin();
    }
}