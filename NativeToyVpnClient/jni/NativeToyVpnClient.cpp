#include <jni.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <sys/time.h>

#include "cc_aznc_android_nativetoyvpn_NativeToyVpnService.h"

#include <android/log.h>

int sock = -1;
struct sockaddr_in server_addr;
int vpnfd = -1;
unsigned long int lastRecvTime = 0;
bool running = true;

void* threadIncoming(void* n)
{
	char buf[4096] = {0};
	int len = 0;
	while(running) {
		len = recvfrom(sock, buf, 4096, 0, NULL, NULL);
		if (len <= 0) {
			if (errno == EAGAIN) {
				usleep(10);
				continue;
			}
			__android_log_print(ANDROID_LOG_DEBUG, "threadIncoming", "sock closed: %d, %s", len, strerror(errno));
			break;
		}
		lastRecvTime = time(NULL);
		if (buf[0] == '\0') {
			__android_log_print(ANDROID_LOG_DEBUG, "threadIncoming", "receive control packet %d bytes", len);
			continue;
		} else {
			__android_log_print(ANDROID_LOG_DEBUG, "threadIncoming", "receive %d bytes", len);
		}

		len = write(vpnfd, buf, len);
		if (len <= 0) {
			__android_log_print(ANDROID_LOG_DEBUG, "threadIncoming", "vpn closed: %d, %s", len, strerror(errno));
			break;
		}
		//__android_log_print(ANDROID_LOG_DEBUG, "threadIncoming", "forward %d bytes", len);
	}

	// notify other thread
	running = false;
	return 0;
}

void* threadOutgoing(void* n)
{
	char buf[4096] = {0};
	int len = 0;
	while(running) {
		len = read(vpnfd, buf, 4096);
		if (len <= 0) {
			if (errno == EAGAIN) {
				usleep(10);
				continue;
			}
			__android_log_print(ANDROID_LOG_DEBUG, "threadOutgoing", "vpn closed: %d, %s", len, strerror(errno));
			break;
		}
		__android_log_print(ANDROID_LOG_DEBUG, "threadOutgoing", "receive %d bytes", len);

		len = sendto(sock, buf, len, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
		if (len <= 0) {
			__android_log_print(ANDROID_LOG_DEBUG, "threadOutgoing", "sock closed: %d", len);
			break;
		}
		//__android_log_print(ANDROID_LOG_DEBUG, "threadOutgoing", "forward %d bytes", len);
	}

	// notify other thread
	running = false;
	return 0;
}

void* threadKeepAlive(void* n)
{
	char buf[4096] = {0};
	int len = 1;

	unsigned long int nowTime, idleTime, lastChkTime;
	while(running) {
		nowTime = time(NULL);
		if (lastChkTime == nowTime) {
			usleep(100000); // 0.1 second
			continue;
		}

		idleTime = nowTime - lastRecvTime;
		if (idleTime > 30) {
			// disconnected?
			break;
		}

		if (idleTime >= 15) {
			sendto(sock, buf, len, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
			__android_log_print(ANDROID_LOG_DEBUG, "threadKeepAlive", "send keep alive %lu", idleTime);
		} else {
			__android_log_print(ANDROID_LOG_DEBUG, "threadKeepAlive", "idle %lu", idleTime);
		}

		lastChkTime = nowTime;
	}

	// notify other thread
	running = false;
	return 0;
}

JNIEXPORT jint JNICALL Java_cc_aznc_android_nativetoyvpn_NativeToyVpnService_getTunnelSock(JNIEnv * env, jobject obj)
{
	if (-1 == sock) {
		sock = socket(AF_INET,SOCK_DGRAM,0);
	}
	fcntl(sock, F_SETFL, O_NONBLOCK);

	return sock;
}

JNIEXPORT jstring JNICALL Java_cc_aznc_android_nativetoyvpn_NativeToyVpnService_startTunnel
	(JNIEnv * env, jobject obj, jstring ip, jint port, jbyteArray secret)
{
	const char *pIp = env->GetStringUTFChars(ip, 0);
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(pIp);
	server_addr.sin_port = htons(port);
	env->ReleaseStringUTFChars(ip, pIp);

	jsize secLen = env->GetArrayLength(secret);
	int ctrlPacketLen = secLen + 1;

	char ctrlPacket[1024] = {0};
	jbyte* pSecret = env->GetByteArrayElements(secret, NULL);
	memcpy(ctrlPacket + 1, pSecret, secLen);
	env->ReleaseByteArrayElements(secret, pSecret, JNI_ABORT);

	int send_num = 0;
	while (send_num++ < 2)
	{
		sendto(sock, ctrlPacket, ctrlPacketLen, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
	}

	char recvBuf[2048] = {0};
	int i = 0;
	for (i = 0; i < 50; ++i) {
		int recvLen = recvfrom(sock, recvBuf, 2048, 0, NULL, NULL);
		if (recvLen > 0 && recvBuf[0] == '\0') {
			recvBuf[recvLen] = 0;
			lastRecvTime = time(NULL);
			return env->NewStringUTF(recvBuf + 1);
		} else {
			usleep(100000);
		}
	}

	return env->NewStringUTF("");
}

JNIEXPORT void JNICALL Java_cc_aznc_android_nativetoyvpn_NativeToyVpnService_tunnelLoop(JNIEnv * env, jobject obj, jint fd)
{
	// let's start tunnel loop thread
	running = true;

	vpnfd = fd;
	__android_log_print(ANDROID_LOG_DEBUG, "tunnelLoop", "get fd %d", fd);

	pthread_t in_thread, out_thread, keep_thread;
	pthread_create(&in_thread, NULL, &threadIncoming, NULL);
	pthread_create(&out_thread, NULL, &threadOutgoing, NULL);
	pthread_create(&keep_thread, NULL, &threadKeepAlive, NULL);
	__android_log_print(ANDROID_LOG_DEBUG, "tunnelLoop", "thread started, looping traffic");

	pthread_join(in_thread,NULL);
	pthread_join(out_thread,NULL);
	pthread_join(keep_thread,NULL);
	__android_log_print(ANDROID_LOG_DEBUG, "tunnelLoop", "thread joined, end loop");

	close(sock);
	close(vpnfd);
	sock = -1;
}

JNIEXPORT void JNICALL Java_cc_aznc_android_nativetoyvpn_NativeToyVpnService_tunnelStop(JNIEnv * env, jobject obj)
{
	running = false;
	__android_log_print(ANDROID_LOG_DEBUG, "tunnelStop", "stopping");
}
