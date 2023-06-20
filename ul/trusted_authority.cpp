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
  element_t pks1, pks2, sks;
  element_init_G1(pks1, sys_param->pairing);
  element_init_G2(pks2, sys_param->pairing);
  element_init_Zr(sks, sys_param->pairing);
  element_t tmp;
  element_init_Zr(tmp, sys_param->pairing);
  size_t sender_key_size = ELEMENT_SIZE * 3;
  // sender pk, sk
  char buf_sender_key[sender_key_size];
  for (int i = 0; i < sys_param->ns; i++) {
    element_random(tmp);
    element_pow_zn(pks1, sys_param->gm1[0], tmp);
    element_pow_zn(pks2, sys_param->gm2[0], tmp);
    element_div(sks, tmp, sys_param->beta[i]);
    element_snprint(buf_sender_key, ELEMENT_SIZE, pks1);
    element_snprint(buf_sender_key + ELEMENT_SIZE, ELEMENT_SIZE, pks2);
    element_snprint(buf_sender_key + 2 * ELEMENT_SIZE, ELEMENT_SIZE, sks);
    channel_sender[i].send(buf_sender_key, sender_key_size);
  }
  element_clear(tmp);
  // receiver pk, sk
  size_t receiver_key_size = ELEMENT_SIZE * 2;
  char buf_pk[sys_param->nr * ELEMENT_SIZE];
  char* buf_pk_ptr = buf_pk;
  char buf_receiver_key[receiver_key_size];
  for (int i = 0; i < sys_param->nr; i++) {
    element_random(sks);
    element_pow_zn(pks1, sys_param->gm1[0], sks);
    element_snprint(buf_receiver_key, ELEMENT_SIZE, pks1);
    memcpy(buf_pk + i * ELEMENT_SIZE, buf_receiver_key, ELEMENT_SIZE);
    element_snprint(buf_receiver_key + ELEMENT_SIZE, ELEMENT_SIZE, sks);
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
  element_clear(sks);
  // set sender ek
  element_t* ek = new element_t[sys_param->nr];
  size_t ek_size = ELEMENT_SIZE * sys_param->nr;
  char buf_ek[ek_size];
  for (int j = 0; j < sys_param->nr; ++j) {
    element_init_G1(ek[j], sys_param->pairing);
  }
  mpz_t temp;
  mpz_init(temp);
  element_t ahat;
  element_init_Zr(ahat, sys_param->pairing);
  for (int i = 0; i < sys_param->ns; ++i) {
    mpz_set_ui(temp, i);
    for (int j = 0; j < sys_param->nr; ++j) {
      if (sys_param->P[i][j]) {
        element_pow_mpz(ahat, sys_param->alpha[j], temp);  // ahat = a ^ i
        element_pow_zn(ek[j], sys_param->gm1[0], ahat);
      } else {
        element_set0(ek[j]);
      }
      element_snprint(buf_ek + j * ELEMENT_SIZE, ELEMENT_SIZE, ek[j]);
    }
    channel_sender[i].send(buf_ek, ek_size);
  }
  element_clear(ahat);
  mpz_clear(temp);
  for (int j = 0; j < sys_param->nr; ++j) {
    element_clear(ek[j]);
  }
  delete[] ek;
  // san
  element_t* RK1 = new element_t[sys_param->nr];
  element_t* RK2 = new element_t[sys_param->ns];
  size_t rk_size = (sys_param->ns +  sys_param->nr) * ELEMENT_SIZE;
  char buf_san[rk_size];
  for (int j = 0; j < sys_param->nr; ++j) {
    element_init_Zr(RK1[j], sys_param->pairing);
    element_set(RK1[j], sys_param->alpha[j]);
    element_snprint(buf_san + j * ELEMENT_SIZE, ELEMENT_SIZE, RK1[j]);
  }
  for (int j = 0; j < sys_param->ns; ++j) {
    element_init_Zr(RK2[j], sys_param->pairing);
    element_set(RK2[j], sys_param->beta[j]);
    element_snprint(buf_san + (j + sys_param->nr) * ELEMENT_SIZE, ELEMENT_SIZE,
                    RK2[j]);
  }
  channel_san->send(buf_san, rk_size);
  for (int j = 0; j < sys_param->nr; ++j) {
    element_clear(RK1[j]);
  }
  for (int j = 0; j < sys_param->ns; ++j) {
    element_clear(RK2[j]);
  }
  delete[] RK1;
  delete[] RK2;
  auto end_keygen = chrono::system_clock::now();
  chrono::duration<double> time_keygen = end_keygen - start_keygen;
  cout << "keygen time " << GREEN << time_keygen.count() << WHITE << " s"
       << endl;
  cout << "------------------------------------------" << endl;
}