#include <future>

#include "network.h"
#include "util.h"

class Server {
 public:
  Server(int, int, int file_number, Entity entity);
  ~Server();
  void get_data();
  void data_to_receiver();
  void channel_init(int, int);

 private:
  Params* sys_param;
  Server_N* channel_sender;
  Server_N* channel_receiver;
  Cipher** cipher;
};