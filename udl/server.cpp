#include "server.h"

void Server::channel_init(int ns, int nr) {
  channel_sender = new Server_N[ns];
  for (int i = 0; i < ns; ++i) {
    std::async(std::launch::async, &Server_N::init, std::ref(channel_sender[i]),
               SERPORT + i);
  }
  channel_receiver = new Server_N[nr];
  for (int i = 0; i < nr; ++i) {
    std::async(std::launch::async, &Server_N::init,
               std::ref(channel_receiver[i]), SERPORT + ns + i);
  }
}

Server::Server(int ns_, int nr_, int file_number, Entity entity) {
  channel_init(ns_, nr_);
  sys_param = new Params;
  sys_param->init(ns_, nr_, file_number, entity);
  cipher = new Cipher*[sys_param->ns];
  for (int i = 0; i < sys_param->ns; ++i) {
    cipher[i] = new Cipher[sys_param->m];
    for (int j = 0; j < sys_param->m; ++j) {
      cipher[i][j].init(sys_param->pairing);
    }
  }
}
Server::~Server() {
  for (int i = 0; i < sys_param->ns; ++i) {
    delete[] cipher[i];
  }
  delete[] cipher;
  delete[] channel_sender;
  delete[] channel_receiver;
  delete sys_param;
}

void Server::get_data() {
  std::function<void(int&)> get_sender_data = [this](int& rank) {
    size_t cipher_size = cipher[rank][0].string_to_cipher(NULL);
    std::unique_ptr<char[]> buf(new char[cipher_size * sys_param->m]);
    channel_sender[rank].receive(buf.get(), cipher_size * sys_param->m);
    for (int j = 0; j < sys_param->m; ++j) {
      cipher[rank][j].string_to_cipher(buf.get() + j * cipher_size);
    }
  };
  for (int i = 0; i < sys_param->ns; ++i) {
    std::async(std::launch::async, std::ref(get_sender_data), std::ref(i));
  }
}

void Server::data_to_receiver() {
  size_t data_size = cipher[0][0].to_string(NULL);
  std::unique_ptr<char[]> buf(new char[data_size * sys_param->m * sys_param->ns]);
  char* buf_ptr = buf.get();
  for (int i = 0; i < sys_param->ns; ++i) {
    for (int j = 0; j < sys_param->m; ++j) {
      cipher[i][j].to_string(buf.get() + data_size * ((i * sys_param->m) + j));
    }
  }
  for (int i = 0; i < sys_param->nr; ++i) {
    std::async(std::launch::async, &Server_N::send,
               std::ref(channel_receiver[i]), buf_ptr,
               data_size * sys_param->m * sys_param->ns);
  }
}