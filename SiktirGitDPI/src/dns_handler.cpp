#include "../include/sgd_core.hpp"
#include "../include/sgd_dns.hpp"

#pragma comment(lib, "ws2_32.lib")

namespace SGDPI {
    namespace DNS {
        bool IsDNSQuery(PacketContext& ctx) {
            if (!ctx.udp) return false;
            return (ntohs(ctx.udp->DstPort) == 53 || ntohs(ctx.udp->SrcPort) == 53);
        }

        void BlockDoH(PacketContext& ctx) {
        }
    }
}