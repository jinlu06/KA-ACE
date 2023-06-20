#ifndef __SANITIZER_H__
#define __SANITIZER_H__
#include <vector>

#include "network.h"
#include "util.h"
using namespace std;

class Sanitizer {
 private:
  element_t** RK;
  element_t* pkr;
  element_t* pks1;
  element_t* pks2;
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