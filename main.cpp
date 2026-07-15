#include "proxy.h"
#include <chrono>

// Реализация методов
DpiBypassProxy::DpiBypassProxy() : serverSocket(INVALID_SOCKET), isRunning(false) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        exit(1);
    }
}

DpiBypassProxy::~DpiBypassProxy() {
    stop();
    WSACleanup();
}

void DpiBypassProxy::log(const std::string& msg) {
    std::lock_guard<std::mutex> lock(logMutex);
    std::cout << "[LOG] " << msg << std::endl;
}

std::string DpiBypassProxy::obfuscateHttpRequest(const std::string& request) {
    std::string result = request;
    
    // 1. Меняем регистр в заголовке Host
    std::regex hostRegex(R"(Host:\s*([^\r\n]+))", std::regex::icase);
    std::smatch match;
    if (std::regex_search(request, match, hostRegex)) {
        std::string hostValue = match[1].str();
        // Перемешиваем регистр
        for (size_t i = 0; i < hostValue.length(); i++) {
            if (i % 2 == 0) {
                hostValue[i] = toupper(hostValue[i]);
            } else {
                hostValue[i] = tolower(hostValue[i]);
            }
        }
        std::string newHost = "Host: " + hostValue;
        result = std::regex_replace(result, hostRegex, newHost);
    }
    
    // 2. Добавляем лишний пробел между методом и URI
    std::regex methodRegex(R"((GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+)", std::regex::icase);
    result = std::regex_replace(result, methodRegex, "$1  ");
    
    // 3. Добавляем случайный заголовок X-Forwarded-For для маскировки
    result += "X-Forwarded-For: 127.0.0.1\r\n";
    
    // 4. Меняем порядок заголовков (если есть Accept)
    std::regex acceptRegex(R"(Accept:\s*[^\r\n]+\r\n)");
    std::smatch acceptMatch;
    if (std::regex_search(request, acceptMatch, acceptRegex)) {
        std::string acceptLine = acceptMatch.str();
        // Удаляем Accept из текущего места
        result = std::regex_replace(result, acceptRegex, "");
        // Добавляем Accept в начало
        size_t pos = result.find("\r\n");
        if (pos != std::string::npos) {
            result.insert(pos + 2, acceptLine);
        }
    }
    
    return result;
}

void DpiBypassProxy::forwardRequest(const std::string& host, int port, const std::string& data, SOCKET clientSocket) {
    SOCKET remoteSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (remoteSocket == INVALID_SOCKET) {
        log("Failed to create remote socket");
        return;
    }
    
    // Разрешаем DNS
    struct addrinfo hints, *result;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result) != 0) {
        log("DNS resolution failed for: " + host);
        closesocket(remoteSocket);
        return;
    }
    
    // Подключаемся
    if (connect(remoteSocket, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
        log("Connection failed to: " + host + ":" + std::to_string(port));
        freeaddrinfo(result);
        closesocket(remoteSocket);
        return;
    }
    freeaddrinfo(result);
    
    // Отправляем модифицированный запрос
    if (send(remoteSocket, data.c_str(), data.length(), 0) == SOCKET_ERROR) {
        log("Send failed");
        closesocket(remoteSocket);
        return;
    }
    
    // Получаем ответ и передаём клиенту
    char buffer[BUFFER_SIZE];
    int bytesRead;
    while ((bytesRead = recv(remoteSocket, buffer, BUFFER_SIZE, 0)) > 0) {
        send(clientSocket, buffer, bytesRead, 0);
    }
    
    closesocket(remoteSocket);
    log("Request forwarded and response sent");
}

void DpiBypassProxy::handleClient(SOCKET clientSocket) {
    char buffer[BUFFER_SIZE];
    std::string request;
    
    // Читаем запрос
    while (true) {
        int bytesRead = recv(clientSocket, buffer, BUFFER_SIZE - 1, 0);
        if (bytesRead <= 0) break;
        buffer[bytesRead] = '\0';
        request += buffer;
        if (request.find("\r\n\r\n") != std::string::npos) break;
        if (request.length() > BUFFER_SIZE * 10) break; // Защита от слишком больших запросов
    }
    
    if (request.empty()) {
        closesocket(clientSocket);
        return;
    }
    
    log("Received request: " + request.substr(0, 100) + "...");
    
    // Извлекаем Host
    std::regex hostRegex(R"(Host:\s*([^\r\n]+))", std::regex::icase);
    std::smatch match;
    std::string host = "example.com";
    int port = 80;
    
    if (std::regex_search(request, match, hostRegex)) {
        host = match[1].str();
        // Удаляем пробелы в начале и конце
        host.erase(0, host.find_first_not_of(" \t\r\n"));
        host.erase(host.find_last_not_of(" \t\r\n") + 1);
    }
    
    // Проверяем, не HTTPS ли это (CONNECT метод)
    if (request.find("CONNECT") == 0) {
        // HTTPS через прокси — просто пробрасываем туннель
        log("HTTPS tunnel requested: " + host);
        std::string response = "HTTP/1.1 200 Connection Established\r\n\r\n";
        send(clientSocket, response.c_str(), response.length(), 0);
        
        // Пробрасываем трафик дальше
        SOCKET remoteSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        struct addrinfo hints, *result;
        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        
        size_t colonPos = host.find(':');
        std::string hostname = host.substr(0, colonPos);
        int remotePort = (colonPos != std::string::npos) ? std::stoi(host.substr(colonPos + 1)) : 443;
        
        if (getaddrinfo(hostname.c_str(), std::to_string(remotePort).c_str(), &hints, &result) == 0) {
            if (connect(remoteSocket, result->ai_addr, (int)result->ai_addrlen) != SOCKET_ERROR) {
                // Проброс данных в обе стороны
                std::thread([=]() {
                    char buf[BUFFER_SIZE];
                    while (true) {
                        int n = recv(clientSocket, buf, BUFFER_SIZE, 0);
                        if (n <= 0) break;
                        send(remoteSocket, buf, n, 0);
                    }
                    closesocket(remoteSocket);
                    closesocket(clientSocket);
                }).detach();
                
                std::thread([=]() {
                    char buf[BUFFER_SIZE];
                    while (true) {
                        int n = recv(remoteSocket, buf, BUFFER_SIZE, 0);
                        if (n <= 0) break;
                        send(clientSocket, buf, n, 0);
                    }
                    closesocket(remoteSocket);
                    closesocket(clientSocket);
                }).detach();
                
                return;
            }
            freeaddrinfo(result);
        }
        closesocket(remoteSocket);
        closesocket(clientSocket);
        return;
    }
    
    // Обычный HTTP — обфусцируем запрос
    std::string modifiedRequest = obfuscateHttpRequest(request);
    log("Request obfuscated, forwarding to: " + host);
    
    // Отправляем на реальный сервер
    forwardRequest(host, port, modifiedRequest, clientSocket);
    closesocket(clientSocket);
}

bool DpiBypassProxy::start() {
    if (isRunning) {
        log("Proxy already running");
        return false;
    }
    
    serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (serverSocket == INVALID_SOCKET) {
        log("Failed to create socket");
        return false;
    }
    
    // Разрешаем переиспользование адреса
    int reuse = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse)) == SOCKET_ERROR) {
        log("Failed to set socket options");
        closesocket(serverSocket);
        return false;
    }
    
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);
    
    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        log("Failed to bind to port " + std::to_string(PORT) + " (may need admin rights)");
        closesocket(serverSocket);
        return false;
    }
    
    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        log("Failed to listen on socket");
        closesocket(serverSocket);
        return false;
    }
    
    isRunning = true;
    log("Proxy started on port " + std::to_string(PORT));
    log("Configure browser to use 127.0.0.1:" + std::to_string(PORT) + " as HTTP proxy");
    log("Press Ctrl+C to stop");
    
    // Основной цикл приёма соединений
    while (isRunning) {
        sockaddr_in clientAddr;
        int addrLen = sizeof(clientAddr);
        SOCKET clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &addrLen);
        
        if (clientSocket == INVALID_SOCKET) {
            if (isRunning) {
                log("Accept failed");
            }
            continue;
        }
        
        // Создаём поток для обработки клиента
        workers.emplace_back(&DpiBypassProxy::handleClient, this, clientSocket);
    }
    
    return true;
}

void DpiBypassProxy::stop() {
    if (!isRunning) return;
    
    isRunning = false;
    if (serverSocket != INVALID_SOCKET) {
        closesocket(serverSocket);
        serverSocket = INVALID_SOCKET;
    }
    
    // Ждём завершения всех потоков
    for (auto& t : workers) {
        if (t.joinable()) {
            t.join();
        }
    }
    workers.clear();
    
    log("Proxy stopped");
}

// ===== ТОЧКА ВХОДА =====
int main() {
    SetConsoleTitleA("DPI Bypass Proxy v1.0");
    system("chcp 65001 > nul"); // UTF-8
    
    std::cout << "╔══════════════════════════════════════════════╗" << std::endl;
    std::cout << "║   🔥 DPI Bypass Proxy v1.0 (C++ порт)     ║" << std::endl;
    std::cout << "║      Без системных драйверов!              ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════════╝" << std::endl;
    std::cout << std::endl;
    
    DpiBypassProxy proxy;
    
    if (!proxy.start()) {
        std::cout << "Ошибка запуска! Возможно, порт " << 8888 << " занят." << std::endl;
        std::cout << "Попробуй запустить от имени администратора." << std::endl;
        system("pause");
        return 1;
    }
    
    std::cout << std::endl;
    std::cout << "Настройки прокси в браузере:" << std::endl;
    std::cout << "  Адрес: 127.0.0.1" << std::endl;
    std::cout << "  Порт:  8888" << std::endl;
    std::cout << "  Тип:   HTTP" << std::endl;
    std::cout << std::endl;
    
    // Ждём сигнала завершения
    std::cout << "Нажми Enter для остановки..." << std::endl;
    std::cin.get();
    
    proxy.stop();
    std::cout << "Программа завершена." << std::endl;
    
    return 0;
}
