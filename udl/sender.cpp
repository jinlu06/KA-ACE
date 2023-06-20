#include "sender.h"

#include <future>
#include <iostream>

#include "network.h"
Sender::Sender(int ns_, int nr_, int file_number, Entity entity, int rank) : rank_(rank) {
  channel_init();
  sys_param = new Params;
  sys_param->init(ns_, nr_, file_number, entity);

  // sys
  size_t buffer_size = sys_param->string_to_param(NULL);
  std::unique_ptr<char[]> buf(new char[buffer_size]);
  channel_ta->receive(buf.get(), buffer_size);
  sys_param->string_to_param(buf.get());
  // pk, sk
  element_init_G1(pk1, sys_param->pairing);
  element_init_G2(pk2, sys_param->pairing);
  element_init_Zr(sk1, sys_param->pairing);
  element_init_Zr(sk2, sys_param->pairing);
  size_t key_size = ELEMENT_SIZE * 4;
  char buf_key[key_size];
  channel_ta->receive(buf_key, key_size);
  element_set_str(pk1, buf_key, 0);
  element_set_str(pk2, buf_key + ELEMENT_SIZE, 0);
  element_set_str(sk1, buf_key + 2 * ELEMENT_SIZE, 0);
  element_set_str(sk2, buf_key + 3 * ELEMENT_SIZE, 0);
  // receiver pk
  char buf_pk[sys_param->nr * ELEMENT_SIZE];
  channel_ta->receive(buf_pk, sys_param->nr * ELEMENT_SIZE);
  pkr = new element_t[sys_param->nr];
  for (int i = 0; i < sys_param->nr; ++i) {
    element_init_G1(pkr[i], sys_param->pairing);
    element_set_str(pkr[i], buf_pk + i * ELEMENT_SIZE, 0);
  }
}

void Sender::channel_init() {
  channel_ta = new Client_N;
  std::async(std::launch::async, &Client_N::init, std::ref(channel_ta),
             DEFPORT + rank_, DEFIP);
  channel_serv = new Client_N;
  std::async(std::launch::async, &Client_N::init, std::ref(channel_serv),
             SERPORT + rank_, DEFIP);
  channel_san = new Client_N;
  std::async(std::launch::async, &Client_N::init, std::ref(channel_san),
             SANPORT + rank_, DEFIP);
}

Sender::~Sender() {
  delete channel_ta;
  delete channel_san;
  delete channel_serv;
  element_clear(sk1);
  element_clear(sk2);
  element_clear(pk2);
  element_clear(pk1);
  if (pkr != nullptr) {
    for (int j = 0; j < sys_param->nr; ++j) {
      element_clear(pkr[j]);
    }
    delete[] pkr;
  }
  delete sys_param;
}

void Sender::encrypt() {
  auto start = std::chrono::system_clock::now();
  Cipher cipher;
  Plain plain;
  cipher.init(sys_param->pairing);
  plain.init(sys_param->pairing);
  size_t cipher_size = cipher.to_string(NULL);
  std::unique_ptr<char[]> buf(new char[cipher_size * sys_param->m]);
  for (int i = 1; i <= sys_param->m; ++i) {
    cipher.set(i);
    plain.set(i, i);
    element_t y;
    element_init_Zr(y, sys_param->pairing);
    element_random(y);
    element_pow_zn(cipher.c0, sys_param->gm2[0], y);  // c0
    element_mul(cipher.c1, pk2, sys_param->gm2[i]);
    element_pow_zn(cipher.c1, cipher.c1, y);  // c1
    element_pairing(cipher.c2, sys_param->gm1[1], sys_param->gm2[sys_param->m]);
    element_pow_zn(cipher.c2, cipher.c2, y);
    element_mul(cipher.c2, plain.M, cipher.c2);  // c2
    element_clear(y);
    cipher.to_string(buf.get() + (i - 1) * cipher_size);
  }
  channel_serv->send(buf.get(), cipher_size * sys_param->m);
  auto end = std::chrono::system_clock::now();
  std::chrono::duration<double> time_enc = end - start;
  std::cout << "enc time " << GREEN << time_enc.count() << WHITE << " s"
            << std::endl;
  std::cout << "------------------------------------------" << std::endl;
}

void Sender::extract() {
  auto start = std::chrono::system_clock::now();
  Aggregate_key agg_key;
  agg_key.init(sys_param->pairing);
  size_t agg_size = agg_key.to_string(NULL);
  char buf[agg_size * sys_param->nr];
  for (int i = 0; i < sys_param->nr; ++i) {
    element_t kij, z1;
    element_init_G1(kij, sys_param->pairing);
    element_init_Zr(z1, sys_param->pairing);
    element_random(z1);
    if (sys_param->P[rank_][i].size() == 0) {
      element_random(kij);
    } else {
      element_set1(kij);
      for (auto j : sys_param->P[rank_][i]) {
        element_mul(kij, kij, sys_param->gm1[sys_param->m + 1 - j]);
      }
      element_pow_zn(kij, kij, sk1);
    }
    element_pow_zn(agg_key.h0, sys_param->gm1[0], z1);
    element_pow_zn(agg_key.h1, pkr[i], z1);
    element_mul(agg_key.h1, agg_key.h1, kij);
    element_pow_zn(agg_key.h2, sys_param->v, sk2);
    element_pow_zn(agg_key.h3, sys_param->v, sk1);
    element_mul(z1, z1, sk2);
    element_pow_zn(agg_key.h4, sys_param->v, z1);
    element_clear(kij);
    element_clear(z1);
    agg_key.to_string(buf + i * agg_size);
  }
  channel_san->send(buf, agg_size * sys_param->nr);
  auto end = std::chrono::system_clock::now();
  std::chrono::duration<double> time_ext = end - start;
  std::cout << "extract time " << GREEN << time_ext.count() << WHITE << " s"
            << std::endl;
  std::cout << "------------------------------------------" << std::endl;
}