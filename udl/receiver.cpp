#include "receiver.h"

#include <algorithm>
#include <future>
#include <iostream>

#include "network.h"
Receiver::Receiver(int ns, int nr, int file_number, Entity entity, int rank)
    : rank_(rank) {
  channel_init(ns);
  sys_param = new Params;
  sys_param->init(ns, nr, file_number, entity);
  size_t buffer_size = sys_param->string_to_param(NULL);
  std::unique_ptr<char[]> buf(new char[buffer_size]);
  channel_ta->receive(buf.get(), buffer_size);
  sys_param->string_to_param(buf.get());

  // pk, sk
  size_t receiver_key_size = ELEMENT_SIZE * 2;
  char buf_key[receiver_key_size];
  element_init_G1(pk1, sys_param->pairing);
  element_init_Zr(sk, sys_param->pairing);
  channel_ta->receive(buf_key, receiver_key_size);
  element_set_str(pk1, buf_key, 0);
  element_set_str(sk, buf_key + ELEMENT_SIZE, 0);
}

void Receiver::channel_init(int ns) {
  channel_ta = new Client_N;
  std::async(std::launch::async, &Client_N::init, std::ref(channel_ta),
             DEFPORT + ns + rank_, DEFIP);
  channel_serv = new Client_N;
  std::async(std::launch::async, &Client_N::init, std::ref(channel_serv),
             SERPORT + ns + rank_, DEFIP);
  channel_san = new Client_N;
  std::async(std::launch::async, &Client_N::init, std::ref(channel_san),
             SANPORT + ns + rank_, DEFIP);
}

Receiver::~Receiver() {
  delete channel_ta;
  delete channel_san;
  delete channel_serv;
  element_clear(pk1);
  element_clear(sk);
  delete sys_param;
}

void Receiver::decrypt() {
  Cipher** cipher = new Cipher*[sys_param->ns];
  for (int i = 0; i < sys_param->ns; ++i) {
    cipher[i] = new Cipher[sys_param->m];
    for (int j = 0; j < sys_param->m; ++j) {
      cipher[i][j].init(sys_param->pairing);
    }
  }
  size_t data_size = cipher[0][0].string_to_cipher(NULL);
  std::unique_ptr<char[]> buf(new char[data_size * sys_param->m * sys_param->ns]);
  channel_serv->receive(buf.get(), data_size * sys_param->m * sys_param->ns);
  for (int i = 0; i < sys_param->ns; ++i) {
    for (int j = 0; j < sys_param->m; ++j) {
      cipher[i][j].string_to_cipher(buf.get() + data_size * ((i * sys_param->m) + j));
    }
  }

  // verify
  std::function<void(int&)> verify = [this, &cipher](int& rank) {
    bool res;
    channel_san->receive(&res, sizeof(bool));
    if (!res) {
      std::cout << "aggreate key not correct, decrypt failed" << std::endl;
      return;
    }
    auto start = std::chrono::system_clock::now();
    San_Aggregate san_agg;
    san_agg.init(sys_param->pairing);
    size_t san_agg_size = san_agg.to_string(NULL);
    char buf_san_agg[san_agg_size];
    channel_san->receive(buf_san_agg, san_agg_size);
    san_agg.string_to_agg(buf_san_agg);
    element_t tmp, tmp2, tmp3, up;
    element_init_G1(tmp, sys_param->pairing);
    element_init_G1(tmp2, sys_param->pairing);
    element_init_Zr(tmp3, sys_param->pairing);
    element_init_GT(up, sys_param->pairing);
    element_t tmp_down, down;
    element_init_G1(tmp_down, sys_param->pairing);
    element_init_GT(down, sys_param->pairing);
    element_t up_down;
    element_init_GT(up_down, sys_param->pairing);
    for (size_t j = 1; j < sys_param->m + 1; ++j) {
      auto it = std::find(sys_param->P[rank][rank_].begin(),
                          sys_param->P[rank][rank_].end(), j);
      if (it == sys_param->P[rank][rank_].end()) {
#ifdef CORRECT_TEST
        std::cout << j << " file can't decrypt" << std::endl;
#endif
        continue;
      }
      element_set1(tmp);
      element_set1(tmp_down);
      for (auto k : sys_param->P[rank][rank_]) {
        if (k == j) continue;
        element_mul(tmp, tmp, sys_param->gm1[sys_param->m + 1 - k + j]);
      }
      element_neg(tmp3, sk);
      element_pow_zn(tmp2, san_agg.d0, tmp3);
      element_mul(tmp, tmp, tmp2);
      element_mul(tmp, tmp, san_agg.d1);
      element_pairing(up, tmp, cipher[rank][j - 1].c0);
      for (auto k : sys_param->P[rank][rank_]) {
        element_mul(tmp_down, tmp_down, sys_param->gm1[sys_param->m + 1 - k]);
      }
      element_pairing(down, tmp_down, cipher[rank][j - 1].c1);
      element_div(up_down, up, down);
      element_mul(up_down, up_down, cipher[rank][j - 1].c2);
#ifdef CORRECT_TEST
      if (element_is1(up_down)) {
        std::cout << j << " decrypt sucess" << std::endl;
      }
#endif
    }
    element_clear(tmp);
    element_clear(tmp2);
    element_clear(tmp3);
    element_clear(tmp_down);
    element_clear(up);
    element_clear(down);
    element_clear(up_down);
    auto end = std::chrono::system_clock::now();
    std::chrono::duration<double> time_dec = end - start;
    std::cout << "dec time " << GREEN << time_dec.count() << WHITE << " s"
              << std::endl;
    std::cout << "------------------------------------------" << std::endl;
  };
  for (int i = 0; i < sys_param->ns; ++i) {
    verify(i);
  }
  for (int i = 0; i < sys_param->ns; ++i) {
    delete[] cipher[i];
  }
  delete[] cipher;
}