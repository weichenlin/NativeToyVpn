#include <netinet/in.h>
#include <string>
#include <stdint.h>

using namespace std;

#define TUNNEL_TIMEOUT 30

class ToyTunnel {
public:
    ToyTunnel(sockaddr_in addr, string vpn_ip);

 	void Send(const char* buf, int len);
 	void Recv(const char* packet, int len);
 	bool Alive();
 	string VpnIp(){return m_vpnIp;};

private:
	sockaddr_in m_addr_in;
	sockaddr* m_pAddr;
	uint32_t m_lastRecvTime;
	string m_vpnIp;
};