#include "IpManager.h"
#include <netinet/in.h>	// struct in_addr
#include <arpa/inet.h>	// inet_aton()
#include <stdint.h>

static unsigned int IpStrToInt(string ip)
{
	struct in_addr ip_addr;
    inet_aton(ip.c_str(), &ip_addr);
    return ntohl(*((unsigned int*)(&ip_addr)));
}

IpManager::IpManager():
	m_IpOffset(0),
	m_CurrentClient(0)
{}

IpManager::~IpManager()
{
	if (m_IpInUse) {
		delete[] m_IpInUse;
	}
}

bool IpManager::SetIpRange(string ipStart, uint32_t ipNum)
{
	if (m_IpInUse) {
		// only allow set range once
		return false;
	}
	m_MaxClient = ipNum;
	m_IpInUse = new bool[m_MaxClient];
    m_IpStart = IpStrToInt(ipStart);

    return true;
}

string IpManager::AssignNewIp()
{
	if (m_CurrentClient >= m_MaxClient) {
		// should throw exception here
		return "";
	}

	struct in_addr ip_addr;
    
    while(true == m_IpInUse[m_IpOffset]) {
    	m_IpOffset = (m_IpOffset + 1) % m_MaxClient;
    }

    m_IpInUse[m_IpOffset] = true;
    ip_addr.s_addr = htonl(m_IpStart + m_IpOffset);
    m_IpOffset = (m_IpOffset + 1) % m_MaxClient;
    m_CurrentClient++;

    return inet_ntoa(ip_addr);
}

void IpManager::ReleaseIp(string ip)
{
	uint32_t ipIndex = IpStrToInt(ip);
	uint32_t offset = ipIndex - m_IpStart;
	m_IpInUse[offset] = false;
	m_CurrentClient--;
}