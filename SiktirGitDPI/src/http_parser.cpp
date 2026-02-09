#include "../include/sgd_http.hpp"
#include <cstring>
#include <algorithm>
#include <string>

namespace SGDPI {
    namespace HTTP {
        bool IsHttpRequest(const char* payload, UINT len) {
            if (len < 10) return false;
            const std::string methods[] = {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "CONNECT ", "OPTIONS ", "TRACE ", "PATCH "};
            for (const auto& m : methods) {
                if (len >= m.length() && memcmp(payload, m.c_str(), m.length()) == 0) return true;
            }
            return false;
        }

        bool FragmentHostHeader(char* payload, UINT len) {
            std::string data(payload, len);
            size_t hostPos = data.find("\r\nHost: ");
            if (hostPos == std::string::npos) hostPos = data.find("\nHost: ");
            
            if (hostPos != std::string::npos) {
                size_t keyPos = hostPos + (data[hostPos] == '\r' ? 2 : 1);
                payload[keyPos] = 'h';
                payload[keyPos+1] = 'O'; 
                payload[keyPos+2] = 's'; 
                payload[keyPos+3] = 't'; 
                return true;
            }
            return false;
        }
    }
}