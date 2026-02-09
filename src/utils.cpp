#include "../include/sgd_utils.hpp"
#include "../include/sgd_config.hpp"
#include <cstring>
#include <iostream>

namespace SGDPI {
    namespace Utils {
        void ApplyPreset(int mode) {
            auto& config = AppConfig::Get();
            config.mode = mode;

            switch (mode) {
                case 1: config.splitPos = 2; config.useFakePacket = false; break;
                case 5: config.splitPos = 1; config.useFakePacket = true; config.ttlValue = 5; break;
                case 9: // En Agresif Mod (Senin Superonline ayarı)
                    config.splitPos = 1;
                    config.useFakePacket = true;
                    config.useDesync = true;
                    config.ttlValue = 3;
                    break;
                default: break;
            }
        }

        void ParseArguments(int argc, char** argv) {
            for (int i = 1; i < argc; ++i) {
                if (argv[i][0] == '-') {
                    // -1, -5, -9 gibi modları yakala
                    int m = std::atoi(&argv[i][1]);
                    if (m > 0) ApplyPreset(m);
                }
            }
        }
    }
}