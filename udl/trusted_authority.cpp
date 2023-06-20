#include "trusted_authority.h"

#include <future>
#include <thread>

#include "network.h"
using namespace std;

void TrustedAuthority::channel_init(int ns, int nr) {
  channel_sender = new Server_N[ns];
  channel_receiver = new Server_N[nr];
  channel_san = new Server_N;
  for (int i = 0; i < nr; ++i) {
    std::async(std::launch::async, &Server_N::init,
               std::ref(channel_receiver[i]), DEFPORT + ns + i);
  }
  for (int i = 0; i < ns; ++i) {
    std::async(std::launch::async, &Server_N::init, std::ref(channel_sender[i]),
               DEFPORT + i);
  }
  std::async(std::launch::async, &Server_N::init, std::ref(*channel_san),
             DEFPORT + ns + nr + 1);
}

TrustedAuthority::~TrustedAuthority() {
  delete[] channel_sender;
  delete[] channel_receiver;
  delete channel_san;
  delete sys_param;
}

TrustedAuthority::TrustedAuthority(int ns_, int nr_, int file_number, Entity entity) {
  channel_init(ns_, nr_);
  sys_param = new Params;
  sys_param->init(ns_, nr_, file_number, entity);
  unsigned int buffer_size = sys_param->to_string(NULL);
  std::unique_ptr<char[]> buf(new char[buffer_size]);
  char* buf_ptr = buf.get();
  sys_param->to_string(buf.get());
  for (int i = 0; i < sys_param->ns; ++i) {
    std::async(std::launch::async, &Server_N::send, ref(channel_sender[i]),
               buf_ptr, buffer_size);
  }
  for (int i = 0; i < sys_param->nr; ++i) {
    std::async(std::launch::async, &Server_N::send, ref(channel_receiver[i]),
               buf_ptr, ref(buffer_size));
  }
  std::async(std::launch::async, &Server_N::send, ref(channel_san), buf_ptr,
             ref(buffer_size));

  auto start_keygen = chrono::system_clock::now();
  // sender pk, sk
  element_t pks1, pks2, sks1, sks2;
  element_init_G1(pks1, sys_param->pairing);
  element_init_G2(pks2, sys_param->pairing);
  element_init_Zr(sks1, sys_param->pairing);
  element_init_Zr(sks2, sys_param->pairing);
  element_t tmp;
  element_init_Zr(tmp, sys_param->pairing);
  size_t sender_key_size = ELEMENT_SIZE * 4;
  // sender pk, sk
  char buf_sender_key[sender_key_size];
  char buf_pk_sender[sys_param->ns * ELEMENT_SIZE * 2];
  char* buf_pk_sender_ptr = buf_pk_sender;
  for (int i = 0; i < sys_param->ns; i++) {
    element_random(tmp);
    element_pow_zn(pks1, sys_param->gm1[0], tmp);
    element_pow_zn(pks2, sys_param->gm2[0], tmp);
    element_set(sks1, tmp);
    element_set(sks2, sys_param->alpha[i + 1]);
    element_snprint(buf_sender_key, ELEMENT_SIZE, pks1);
    element_snprint(buf_sender_key + ELEMENT_SIZE, ELEMENT_SIZE, pks2);
    element_snprint(buf_sender_key + 2 * ELEMENT_SIZE, ELEMENT_SIZE, sks1);
    element_snprint(buf_sender_key + 3 * ELEMENT_SIZE, ELEMENT_SIZE, sks2);
    memcpy(buf_pk_sender + i * ELEMENT_SIZE * 2, buf_sender_key,
           ELEMENT_SIZE * 2);
    channel_sender[i].send(buf_sender_key, sender_key_size);
  }
  element_clear(tmp);
  std::async(std::launch::async, &Server_N::send, ref(channel_san),
             buf_pk_sender_ptr, sys_param->ns * ELEMENT_SIZE * 2);
  // receiver pk, sk
  size_t receiver_key_size = ELEMENT_SIZE * 2;
  char buf_pk[sys_param->nr * ELEMENT_SIZE];
  char* buf_pk_ptr = buf_pk;
  char buf_receiver_key[receiver_key_size];
  for (int i = 0; i < sys_param->nr; i++) {
    element_random(sks1);
    element_pow_zn(pks1, sys_param->gm1[0], sks1);
    element_snprint(buf_receiver_key, ELEMENT_SIZE, pks1);
    memcpy(buf_pk + i * ELEMENT_SIZE, buf_receiver_key, ELEMENT_SIZE);
    element_snprint(buf_receiver_key + ELEMENT_SIZE, ELEMENT_SIZE, sks1);
    channel_receiver[i].send(buf_receiver_key, receiver_key_size);
  }
  for (int i = 0; i < sys_param->ns; i++) {
    std::async(std::launch::async, &Server_N::send, ref(channel_sender[i]),
               buf_pk_ptr, sys_param->nr * ELEMENT_SIZE);
  }
  std::async(std::launch::async, &Server_N::send, ref(channel_san), buf_pk_ptr,
             sys_param->nr * ELEMENT_SIZE);
  element_clear(pks1);
  element_clear(pks2);
  element_clear(sks1);
  element_clear(sks2);
  // san
  element_t rk;
  char buf_rk[sys_param->ns * sys_param->nr * ELEMENT_SIZE];
  element_init_G1(rk, sys_param->pairing);
  for (int i = 0; i < sys_param->ns; ++i) {
    for (int j = 0; j < sys_param->nr; ++j) {
      if (sys_param->P[i][j].size() == 0)
        element_random(rk);
      else {
        element_set1(rk);
        element_t tmp;
        element_init_G1(tmp, sys_param->pairing);
        for (auto z : sys_param->P[i][j]) {
          element_pow_zn(tmp, sys_param->gm1[sys_param->m + 1 - z],
                         sys_param->alpha[i + 1]);
          element_mul(rk, rk, tmp);
        }
        element_clear(tmp);
      }
      element_snprint(buf_rk + ELEMENT_SIZE * (i * sys_param->nr + j),
                      ELEMENT_SIZE, rk);
    }
  }
  element_clear(rk);
  channel_san->send(buf_rk, sys_param->ns * sys_param->nr * ELEMENT_SIZE);
  auto end_keygen = chrono::system_clock::now();
  chrono::duration<double> time_keygen = end_keygen - start_keygen;
  cout << "keygen time " << GREEN << time_keygen.count() << WHITE << " s"
       << endl;
  cout << "------------------------------------------" << endl;
}