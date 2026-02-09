#include "../include/sgd_tls.hpp"
#include <cstring>

namespace SGDPI {
    namespace TLS {
        bool IsClientHello(const char* payload, UINT len) {
            if (len < 40) return false;
            return (payload[0] == 0x16 && payload[5] == 0x01);
        }

        std::string ExtractSNI(const char* data, UINT len) {
            if (len < 43) return "";
            UINT pos = 43; 
            
            if (pos + 2 > len) return "";
            UINT16 sessionIdLen = data[pos];
            pos += 1 + sessionIdLen;

            if (pos + 2 > len) return "";
            UINT16 cipherSuitesLen = (data[pos] << 8) + data[pos+1];
            pos += 2 + cipherSuitesLen;

            if (pos + 1 > len) return "";
            UINT16 compMethodsLen = data[pos];
            pos += 1 + compMethodsLen;

            if (pos + 2 > len) return "";
            UINT16 extensionsLen = (data[pos] << 8) + data[pos+1];
            pos += 2;

            UINT limit = pos + extensionsLen;
            if (limit > len) limit = len;

            while (pos + 4 <= limit) {
                UINT16 extType = (data[pos] << 8) + data[pos+1];
                UINT16 extLen = (data[pos+2] << 8) + data[pos+3];
                pos += 4;

                if (extType == 0x0000) { 
                    if (pos + 5 > limit) break;
                    UINT16 listLen = (data[pos] << 8) + data[pos+1];
                    if (pos + 2 + listLen > limit) break;
                    
                    if (data[pos+2] == 0x00) { 
                        UINT16 nameLen = (data[pos+3] << 8) + data[pos+4];
                        if (pos + 5 + nameLen > limit) break;
                        return std::string(data + pos + 5, nameLen);
                    }
                }
                pos += extLen;
            }
            return "";
        }

        bool MangleSNI(char* payload, UINT len) {
            return true;
        }
    }
}