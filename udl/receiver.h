#include "network.h"
#include "util.h"
class Receiver {
 public:
  Receiver(int ns, int nr, int file_number, Entity entity, int);
  ~Receiver();
  void channel_init(int);
  void decrypt();

 private:
  Params* sys_param;
  Client_N* channel_ta;
  Client_N* channel_serv;
  Client_N* channel_san;
  int rank_;
  element_t sk;
  element_t pk1;
};