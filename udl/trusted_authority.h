#ifndef TRUSTED_AUTHORITY_H
#define TRUSTED_AUTHORITY_H

#include <pbc.h>

#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "network.h"
#include "util.h"
using namespace std;
class TrustedAuthority {
 public:
  TrustedAuthority(int, int, int, Entity);
  ~TrustedAuthority();
  void channel_init(int, int);

 private:
  Params* sys_param;
  Server_N* channel_sender;
  Server_N* channel_receiver;
  Server_N* channel_san;
};

#endif