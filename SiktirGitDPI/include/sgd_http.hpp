#pragma once
#include "sgd_core.hpp"

namespace SGDPI {
    namespace HTTP {
        bool IsHttpRequest(const char* payload, UINT len);
        bool FragmentHostHeader(char* payload, UINT len);
    }
}