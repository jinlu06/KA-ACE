#ifndef __SANITIZER_H__
#define __SANITIZER_H__
#include <vector>

#include "network.h"
#include "util.h"
using namespace std;

class Sanitizer {
 private:
  element_t* RK1;
  element_t* RK2;
  element_t* pkr;
  Params* sys_param;
  Client_N* channel_ta;
  Server_N* channel_sender;
  Server_N* channel_receiver;

 public:
  Sanitizer(int, int, int file_number, Entity entity);
  ~Sanitizer();
  void channel_init(int, int);
  void san();
};

#endif