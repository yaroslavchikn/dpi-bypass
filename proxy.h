#pragma once
#ifndef PROXY_H
#define PROXY_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <algorithm>
#include <regex>
#include <sstream>

#pragma comment(lib, "ws2_32.lib")

class DpiBypassProxy {
private:
    SOCKET serverSocket;
    bool isRunning;
    std::vector<std::thread> workers;
    std::mutex logMutex;
    
    // Конфигурация
    static constexpr int PORT = 8888;
    static constexpr int BUFFER_SIZE = 8192;
    
    void log(const std::string& msg);
    void handleClient(SOCKET clientSocket);
    std::string obfuscateHttpRequest(const std::string& request);
    void forwardRequest(const std::string& host, int port, const std::string& data, SOCKET clientSocket);
    
public:
    DpiBypassProxy();
    ~DpiBypassProxy();
    bool start();
    void stop();
    bool isActive() const { return isRunning; }
};

#endif
