#pragma once
#include "sgd_core.hpp"

namespace SGDPI {
    namespace DNS {
        bool IsDNSQuery(PacketContext& ctx);
        void BlockDoH(PacketContext& ctx);
    }
}