#ifndef NETWORK_H
#define NETWORK_H

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>


#define BUFSIZE 65536

union Sockaddr {
  struct sockaddr addr;
  struct sockaddr_in addr_in;
};


class Server_N {
public:
  Server_N() {sockfd = -1; sockfd_new = -1;}
  void init(const int portno);
  ~Server_N();
  int server_listen(const int portno);
  void server_accept();
  void send(void* buffer, const unsigned len);
  void receive(void* buffer, const unsigned len);
private:
  int sockfd;
  int sockfd_new;
};


class Client_N {
public:
Client_N() {sockfd = -1;}
  // void init(const int portno, const char* host);
  void init(const int, const char* host = "127.0.0.1");
  ~Client_N();
  void client_connect(int* sock, const char* host, const int portno);
  void send(void* buffer, const unsigned len);
  void receive(void* buffer, const unsigned len);
private:
  int sockfd;
};
#endif  // ifndef NETWORK_H