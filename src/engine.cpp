#include "../include/sgd_engine.hpp"
#include "../include/sgd_tls.hpp"
#include "../include/sgd_http.hpp"
#include "../include/sgd_dns.hpp"
#include <iostream>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")

namespace SGDPI {

    DeepEngine::DeepEngine() {
        hDivert = INVALID_HANDLE_VALUE;
        len = 0;
        memset(&addr, 0, sizeof(addr));
        memset(buffer, 0, sizeof(buffer));
        memset(fragBuffer, 0, sizeof(fragBuffer));
    }

    DeepEngine::~DeepEngine() {
        if (hDivert != INVALID_HANDLE_VALUE) {
            WinDivertClose(hDivert);
        }
    }

    void SendFake(HANDLE hDivert, char* pkt, UINT pktLen, WINDIVERT_ADDRESS* addr, UINT8 ttl) {
        char fake[1500];
        memcpy(fake, pkt, pktLen);
        PWINDIVERT_IPHDR ip = (PWINDIVERT_IPHDR)fake;
        PWINDIVERT_TCPHDR tcp = (PWINDIVERT_TCPHDR)(fake + (ip->HdrLength * 4));

        ip->TTL = ttl;
        tcp->SeqNum = htonl(ntohl(tcp->SeqNum) - 1000); // Sequence numarasını kaydır
        tcp->Checksum = 0xAAAA; // Bilerek bozuk checksum

        WinDivertSend(hDivert, fake, pktLen, NULL, addr);
    }

    void DeepEngine::InjectFragmentedPacket(char* originalPacket, UINT originalLen, PacketContext& ctx, int splitPos) {
        if (!ctx.ip || !ctx.tcp) return;

        UINT ipHeaderLen = ctx.ip->HdrLength * 4;
        UINT tcpHeaderLen = ctx.tcp->HdrLength * 4;
        UINT headerTotal = ipHeaderLen + tcpHeaderLen;

        char* payloadStart = originalPacket + headerTotal;
        UINT payloadSize = ctx.payloadLen;

        if (payloadSize <= splitPos) return;

        memcpy(fragBuffer, originalPacket, headerTotal);
        memcpy(fragBuffer + headerTotal, payloadStart, splitPos);
        UINT frag1Len = headerTotal + splitPos;
        PWINDIVERT_IPHDR ip1 = (PWINDIVERT_IPHDR)fragBuffer;
        ip1->Length = htons((UINT16)frag1Len);
        WinDivertHelperCalcChecksums(fragBuffer, frag1Len, &addr, 0);
        WinDivertSend(hDivert, fragBuffer, frag1Len, NULL, &addr);

        memcpy(fragBuffer, originalPacket, headerTotal);
        memcpy(fragBuffer + headerTotal, payloadStart + splitPos, payloadSize - splitPos);
        UINT frag2Len = headerTotal + (payloadSize - splitPos);
        PWINDIVERT_IPHDR ip2 = (PWINDIVERT_IPHDR)fragBuffer;
        PWINDIVERT_TCPHDR tcp2 = (PWINDIVERT_TCPHDR)(fragBuffer + ipHeaderLen);
        ip2->Length = htons((UINT16)frag2Len);
        tcp2->SeqNum = htonl(ntohl(tcp2->SeqNum) + splitPos);
        WinDivertHelperCalcChecksums(fragBuffer, frag2Len, &addr, 0);
        WinDivertSend(hDivert, fragBuffer, frag2Len, NULL, &addr);
    }

    void DeepEngine::Run(const std::string& filter) {
        std::cout << "[*] SiktirGitDPI v3.0 [SUPERONLINE EDITION]" << std::endl;

        hDivert = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
        if (hDivert == INVALID_HANDLE_VALUE) return;

        while (TRUE) {
            if (!WinDivertRecv(hDivert, buffer, sizeof(buffer), &len, &addr)) continue;

            PacketContext ctx = { 0 };
            UINT8 protocol = 0;
            WinDivertHelperParsePacket(buffer, len, (PWINDIVERT_IPHDR*)&ctx.ip, NULL, &protocol, NULL, NULL, (PWINDIVERT_TCPHDR*)&ctx.tcp, (PWINDIVERT_UDPHDR*)&ctx.udp, (PVOID*)&ctx.payload, &ctx.payloadLen, NULL, NULL);

            bool handled = false;
            if (ctx.tcp && ctx.payloadLen > 0) {
                if (TLS::IsClientHello(ctx.payload, ctx.payloadLen)) {
                    std::string host = TLS::ExtractSNI(ctx.payload, ctx.payloadLen);
                    if (!host.empty()) {
                        std::cout << "[BYPASS] " << host << " -> Double-Fake + 1-Byte Split" << std::endl;

                        // Önce DPI'ı şaşırtmak için sahte paketleri yolla
                        SendFake(hDivert, buffer, len, &addr, 2);
                        SendFake(hDivert, buffer, len, &addr, 4);

                        // Sonra paketi en baştan böl
                        InjectFragmentedPacket(buffer, len, ctx, 1);
                        handled = true;
                    }
                }
            }

            if (!handled) {
                WinDivertHelperCalcChecksums(buffer, len, &addr, 0);
                WinDivertSend(hDivert, buffer, len, NULL, &addr);
            }
        }
    }

    void DeepEngine::RecomputeChecksums(char* buffer, UINT length, WINDIVERT_ADDRESS* addr) {
        WinDivertHelperCalcChecksums(buffer, length, addr, 0);
    }
}