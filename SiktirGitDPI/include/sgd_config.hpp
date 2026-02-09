#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace SGDPI {
    struct AppConfig {
        bool enableHttpBypass;
        bool enableTlsBypass;
        bool enableDnsRedirection;
        bool fragmentPackets;
        int fragmentSize;
        std::string dnsServerIP;
        uint16_t dnsServerPort;
        
        static AppConfig& Get() {
            static AppConfig instance;
            return instance;
        }

    private:
        AppConfig() : 
            enableHttpBypass(true), 
            enableTlsBypass(true), 
            enableDnsRedirection(false),
            fragmentPackets(false),
            fragmentSize(1),
            dnsServerIP("8.8.8.8"), 
            dnsServerPort(53) {}
    };
}