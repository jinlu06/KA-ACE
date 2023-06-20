#include "network.h"
#include <iostream>
int main(int argc, char* argv[]) {
int port = 5000;
char hostname[] = "127.0.0.1";

if(strcmp(argv[1], "0") == 0) {
  std::cout << "0" << std::endl;
  Server_N ser;
  ser.init(port);
  // 1 <--> 2
  char S_pack[20] = "hello world\n";
  ser.send(S_pack, 20);
  char S_pack1[100];
  ser.receive(S_pack, 100);
  std::cout << S_pack1 << std::endl;
} else {
    Client_N client;
    client.init(port, hostname);
    char S_pack[20];
    client.receive(S_pack, 20);
    std::cout << S_pack;
    char S_pack1[100] = "hello world\n";
    client.send(S_pack, 100);
}
  return 0;
}