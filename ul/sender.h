#include "network.h"
#include "util.h"

class Sender {
 public:
  Sender(int, int, int, Entity entity, int rank);
  ~Sender();
  void channel_init();
  void encrypt();
  void extract();

 private:
  Params* sys_param;
  Client_N* channel_ta;
  Client_N* channel_serv;
  Client_N* channel_san;
  int rank_;
  element_t sk;
  element_t pk1;
  element_t pk2;
  element_t* ek;  // Ek, 如果P(i, j) = false, set ek[j] = 0;
  element_t* pkr;
};
