#pragma once
#include "sgd_core.hpp"
#include "sgd_config.hpp"
#include <string>

namespace SGDPI {
    class DeepEngine {
    private:
        HANDLE hDivert;
        char buffer[65535];
        char fragBuffer[65535];
        WINDIVERT_ADDRESS addr;
        UINT len;
        
        void InjectFragmentedPacket(char* originalPacket, UINT originalLen, PacketContext& ctx, int splitPos);
        void RecomputeChecksums(char* buffer, UINT length, WINDIVERT_ADDRESS* addr);

    public:
        DeepEngine();
        ~DeepEngine();
        void Run(const std::string& filter);
    };
}