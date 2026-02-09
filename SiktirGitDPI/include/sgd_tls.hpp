#pragma once
#include "sgd_core.hpp"

namespace SGDPI {
    namespace TLS {
        bool IsClientHello(const char* payload, UINT len);
        std::string ExtractSNI(const char* payload, UINT len);
        bool MangleSNI(char* payload, UINT len);
    }
}