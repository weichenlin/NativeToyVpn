/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>

#include <unordered_map>
#include <string>
#include "ToyTunnel.h"
#include "IpManager.h"

// disable printf?
//#define printf(...)

#ifdef __linux__

// There are several ways to play with this program. Here we just give an
// example for the simplest scenario. Let us say that a Linux box has a
// public IPv4 address on eth0. Please try the following steps and adjust
// the parameters when necessary.
//
// # Enable IP forwarding
// echo 1 > /proc/sys/net/ipv4/ip_forward
//
// # Pick a range of private addresses and perform NAT over eth0.
// iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -o eth0 -j MASQUERADE
//
// # Create a TUN interface.
// ip tuntap add dev tun0 mode tun
//
// # ** if your box didn't support tuntap, use this command instead
// tunctl -n -t tun0
//
// # Set the addresses and bring up the interface.
// ifconfig tun0 10.0.0.1 dstaddr 10.0.0.2 up
//
// # Create a server on port 8000 with shared secret "test".
// ./ToyVpnServer tun0 8000 test -m 1400 -a 10.0.0.2 32 -d 8.8.8.8 -r 0.0.0.0 0
//
// This program only handles a session at a time. To allow multiple sessions,
// multiple servers can be created on the same port, but each of them requires
// its own TUN interface. A short shell script will be sufficient. Since this
// program is designed for demonstration purpose, it performs neither strong
// authentication nor encryption. DO NOT USE IT IN PRODUCTION!

/*
 a multi client tunnel:
 echo 1 > /proc/sys/net/ipv4/ip_forward
 tunctl -n -t tun10
 ifconfig tun10 10.0.0.0/8 up
 iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -o eth0 -j MASQUERADE
*/
#include <net/if.h>
#include <linux/if_tun.h>

static int GetInterface(char *name)
{
    int interface = open("/dev/net/tun", O_RDWR | O_NONBLOCK);

    ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

    if (ioctl(interface, TUNSETIFF, &ifr)) {
        perror("Cannot get TUN interface");
        exit(1);
    }

    return interface;
}

#else

#error Sorry, you have to implement this part by yourself.

#endif


using namespace std;

// *** global variables ***
// fd of the tun interface
int gTunFD;

// fd of local socket
int gSrvSock;

// general parameter for client, without assign a ip address
string gParams;

// get tunnel by wan ip, used when recv data from client
unordered_map <string, void*> gClientAddrToTunnel;

// get tunnel by vpn ip, used when got data from tunnel to client
unordered_map <string, void*> gVpnAddrToTunnel;

// a simple password for login
string gSecret;

// our ip manager
IpManager* gIpMgr;

static string BuildGeneralParameters(int argc, char **argv)
{
    string param;
    // Well, for simplicity, we just concatenate them (almost) blindly.
    for (int i = 4; i < argc; ++i) {
        char *parameter = argv[i];
        int length = strlen(parameter);
        char delimiter = ',';

        // If it looks like an option, prepend a space instead of a comma.
        if (length == 2 && parameter[0] == '-') {
            ++parameter;
            --length;
            delimiter = ' ';
        }

        // Append the delimiter and the parameter.
        if (param.size() > 0) {
            param.append(1, delimiter);
        }
        param.append(parameter, length);
    }

    return param;
}

static string BuildClientParameters(string ip)
{
    return gParams + " a," + ip + ",32";
}

typedef struct iphdr{
    // little endian
    uint8_t ip_hl:4, ip_v:4;
    uint8_t ip_tos;
    uint16_t ip_len;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t ip_ttl;
    uint8_t ip_p;
    uint16_t ip_sum;
    uint32_t ip_src;
    uint32_t ip_dst;
} iphdr;

typedef struct netport{
    uint16_t src;
    uint16_t dst;
} netport;

static string ParseHeader(const char* packet)
{
    if (*packet == '\0') {
        return "keep-alive";
    }

    iphdr* hdr = (iphdr*)packet;
    netport* port = (netport*)(packet + (hdr->ip_hl * 4));

    string info;
    // to prevent ambigious in some compiler, use unsigned long long
    unsigned long long portnum;
    info.append(inet_ntoa(*((in_addr*)&hdr->ip_src)));
    info.append(":");
    info.append(to_string(portnum = ntohs(port->src)));
    info.append(" -> ");
    info.append(inet_ntoa(*((in_addr*)&hdr->ip_dst)));
    info.append(":");
    info.append(to_string(portnum = ntohs(port->dst)));

    return info;
}

// extract ip address from packet and make key
static string GetVpnAddr(const char* packet)
{
    iphdr* hdr = (iphdr*)packet;

    string key;
    key.append((char*)&hdr->ip_dst, sizeof(hdr->ip_dst));

    return key;
}

// make key from ip string
static string GetVpnAddr(string ip)
{
    string key;
    struct in_addr in_ip;
    inet_aton(ip.c_str(), &in_ip);
    key.append((char*)&in_ip, sizeof(in_ip));

    return key;
}

static bool ClientAuth(const char* packet)
{
    if (strcmp(gSecret.c_str(), packet + 1) == 0) {
        return true;
    }

    return false;
}

static void ProcessClientPacket(const char* packet, int len, sockaddr_in client_sockaddr)
{
    socklen_t addrlen = sizeof(sockaddr_in);
    string clientAddr = string((char*)&client_sockaddr, 8);
    if (gClientAddrToTunnel.count(clientAddr) > 0) {
        // found client
        ToyTunnel* pClient = (ToyTunnel*)gClientAddrToTunnel[clientAddr];
        printf("data from client %s [%s:%d]\n",
            pClient->VpnIp().c_str(), inet_ntoa(client_sockaddr.sin_addr), ntohs(client_sockaddr.sin_port));
        string info = ParseHeader(packet);
        printf("\t\t----%s\n", info.c_str());
        pClient->Recv(packet, len);
    } else {
        // new client?
        if (packet[0] != 0) {
            // not control packet nor valid client
            return;
        }

        // handshake new client
        if (ClientAuth(packet)) {
            printf("got new client : ");
            string new_ip = gIpMgr->AssignNewIp();
            if (new_ip.empty()) {
                printf("ERROR: no more ip allowed\n");
                return;
            }
            printf("assign new ip %s\n", new_ip.c_str());
            string vpnAddr = GetVpnAddr(new_ip);
            string params = BuildClientParameters(new_ip);

            char parameters[2048] = {0};
            memcpy(parameters + 1, params.c_str(), params.size());

            ToyTunnel* pClient = new ToyTunnel(client_sockaddr, new_ip);
            gClientAddrToTunnel[clientAddr] = pClient;
            gVpnAddrToTunnel[vpnAddr] = pClient;
            pClient->Send(parameters, params.size() + 1);
        }
    }
}

static void ProcessTunnelPacket(const char* packet, int len)
{
    string vpnAddr = GetVpnAddr(packet);
    if (gVpnAddrToTunnel.count(vpnAddr) > 0) {
        ToyTunnel* pClient = (ToyTunnel*)gVpnAddrToTunnel[vpnAddr];
        pClient->Send(packet, len);
        printf("data to client %s\n", pClient->VpnIp().c_str());
        string info = ParseHeader(packet);
        printf("\t\t----%s\n", info.c_str());
    } else {
        //error, got packet to unknown ip, ignore it
        printf("WARN: got packet for unknown ip\n");
        string info = ParseHeader(packet);
        printf("\t\t----%s\n", info.c_str());
    }
}

static void CheckDeadClient()
{
    // check every seconds
    static uint32_t lastCheckTime = time(NULL);
    uint32_t now = time(NULL);
    if (now == lastCheckTime) {
        return;
    }
    lastCheckTime = now;

    auto it = gClientAddrToTunnel.begin();
    while(it != gClientAddrToTunnel.end()) {
        ToyTunnel* pClient = (ToyTunnel*)it->second;
        if (pClient->Alive()) {
            it++;
            continue;
        }

        string ip = pClient->VpnIp();
        string vpnAddr = GetVpnAddr(ip);
        gIpMgr->ReleaseIp(ip);
        gVpnAddrToTunnel.erase(vpnAddr);
        it = gClientAddrToTunnel.erase(it);
        delete pClient;
        printf("client %s timed out, release ip\n", ip.c_str());
    }
}

static void ServerLoop()
{
    // main loop
    char packet[2048] = {0};
    struct timeval timeout;
    bool idle;
    while (true) {
        idle = true;
        sockaddr_in client_sockaddr;
        socklen_t addrlen = sizeof(sockaddr_in);
        int ret = recvfrom(gSrvSock, packet, sizeof(packet), 0, (sockaddr *)&client_sockaddr, &addrlen);
        if (ret > 0) {
            idle = false;
            ProcessClientPacket(packet, ret, client_sockaddr);
        }

        ret = read(gTunFD, packet, sizeof(packet));
        if (ret > 0) {
            idle = false;
            ProcessTunnelPacket(packet, ret);
        }

        CheckDeadClient();

        if (idle) {
            usleep(10);
        }
    }
}

static void StartServer(char *port)
{
	gSrvSock = socket(AF_INET, SOCK_DGRAM, 0);
    int flag = 1;
    setsockopt(gSrvSock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    
    // Accept packets received on any local address.
    sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(atoi(port));
    
    // Call bind(2) in a loop since Linux does not have SO_REUSEPORT.
    while (bind(gSrvSock, (sockaddr *)&server_addr, sizeof(server_addr))) {
        if (errno != EADDRINUSE) {
            printf("get_tunnel error 1\n");
            return;
        }
        usleep(100000);
    }
    fcntl(gSrvSock, F_SETFL, O_NONBLOCK);

    ServerLoop();
}

void SendToClient(sockaddr* dst_addr, const char* buf, int len)
{
    sendto(gSrvSock, buf, len, MSG_NOSIGNAL, dst_addr, sizeof(*dst_addr));
}

void SendToTunnel(const char* buf, int len)
{
    write(gTunFD, buf, len);
}

int main(int argc, char **argv)
{
    if (argc < 5) {
        printf("Usage: %s <tunN> <port> <secret> options...\n"
               "\n"
               "Options:\n"
               "  -m <MTU> for the maximum transmission unit\n"
               //"  -a <address> <prefix-length> for the private address\n"
               "  -r <address> <prefix-length> for the forwarding route\n"
               "  -d <address> for the domain name server\n"
               "  -s <domain> for the search domain\n"
               "\n"
               "Note that TUN interface needs to be configured properly\n"
               "BEFORE running this program. For more information, please\n"
               "read the comments in the source code.\n\n", argv[0]);
        exit(1);
    }
    
    // init global variables
    // Parse the arguments and set the parameters.
    gParams = BuildGeneralParameters(argc, argv);

    // Get TUN interface.
    gTunFD = GetInterface(argv[1]);

    // password
    gSecret = argv[3];

    // ip manager
    gIpMgr = new IpManager();
    gIpMgr->SetIpRange("10.0.0.1", 255);

    StartServer(argv[2]);

    exit(0);
}