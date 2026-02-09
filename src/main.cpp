#include "../include/sgd_core.hpp"
#include "../include/sgd_utils.hpp"
#include "../include/sgd_engine.hpp" 
#include <csignal>

void SignalHandler(int signum) {
    exit(signum);
}

int main(int argc, char** argv) {
    SetConsoleTitleA("SGDPI - Kernel Level Packet Filter");
    SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
    
    signal(SIGINT, SignalHandler);
    signal(SIGTERM, SignalHandler);

    SGDPI::Utils::ParseArguments(argc, argv);

    std::string filter = "outbound and !loopback and (tcp.DstPort == 80 or tcp.DstPort == 443 or udp.DstPort == 53)";
    
    SGDPI::DeepEngine engine;
    engine.Run(filter);

    return 0;
}