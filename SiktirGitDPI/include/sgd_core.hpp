#pragma once
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <atomic>
#include "windivert.h"

namespace SGDPI {
    struct PacketContext {
        WINDIVERT_IPHDR* ip;
        WINDIVERT_TCPHDR* tcp;
        WINDIVERT_UDPHDR* udp;
        char* payload;
        UINT payloadLen;
    };
}