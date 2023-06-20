#include "sanitizer.h"

#include <future>
#include <iostream>

#include "network.h"

Sanitizer::Sanitizer(int ns, int nr, int file_number, Entity entity) {
  channel_init(ns, nr);
  sys_param = new Params;
  sys_param->init(ns, nr, file_number, entity);
  size_t buffer_size = sys_param->string_to_param(NULL);
  std::unique_ptr<char[]> buf(new char[buffer_size]);
  channel_ta->receive(buf.get(), buffer_size);
  sys_param->string_to_param(buf.get());
  // receiver pk
  char buf_pk[sys_param->nr * ELEMENT_SIZE];
  channel_ta->receive(buf_pk, sys_param->nr * ELEMENT_SIZE);
  pkr = new element_t[sys_param->nr];
  for (int i = 0; i < sys_param->nr; ++i) {
    element_init_G1(pkr[i], sys_param->pairing);
    element_set_str(pkr[i], buf_pk + i * ELEMENT_SIZE, 0);
  }
  // RK
  RK1 = new element_t[sys_param->nr];
  RK2 = new element_t[sys_param->ns];
  size_t rk_size = (sys_param->nr + sys_param->ns) * ELEMENT_SIZE;
  char buf_rk[rk_size];
  channel_ta->receive(buf_rk, rk_size);
  for (int j = 0; j < sys_param->nr; ++j) {
    element_init_Zr(RK1[j], sys_param->pairing);
    element_set_str(RK1[j], buf_rk + j * ELEMENT_SIZE, 0);
  }
  for (int j = 0; j < sys_param->ns; ++j) {
    element_init_Zr(RK2[j], sys_param->pairing);
    element_set_str(RK2[j], buf_rk + (j + sys_param->nr) * ELEMENT_SIZE, 0);
  }
}

void Sanitizer::channel_init(int ns, int nr) {
  channel_ta = new Client_N;
  std::async(std::launch::async, &Client_N::init, std::ref(channel_ta),
             DEFPORT + (ns + nr) + 1, DEFIP);
  channel_sender = new Server_N[ns];
  channel_receiver = new Server_N[nr];
  for (int i = 0; i < ns; ++i) {
    std::async(std::launch::async, &Server_N::init, std::ref(channel_sender[i]),
               SANPORT + i);
  }
  for (int i = 0; i < nr; ++i) {
    std::async(std::launch::async, &Server_N::init,
               std::ref(channel_receiver[i]), SANPORT + ns + i);
  }
}

Sanitizer::~Sanitizer() {
  delete channel_ta;
  delete[] channel_sender;
  delete[] channel_receiver;
  if (RK1 != nullptr) {
    for (int j = 0; j < sys_param->nr; ++j) {
      element_clear(RK1[j]);
    }
    for (int j = 0; j < sys_param->ns; ++j) {
      element_clear(RK2[j]);
    }
    delete[] RK1;
    delete[] RK2;
  }
  if (pkr != nullptr) {
    for (int j = 0; j < sys_param->nr; ++j) {
      element_clear(pkr[j]);
    }
    delete[] pkr;
  }
  delete sys_param;
}

void Sanitizer::san() {
  Aggregate_key** agg_key;
  agg_key = new Aggregate_key*[sys_param->ns];
  for (int i = 0; i < sys_param->ns; ++i) {
    agg_key[i] = new Aggregate_key[sys_param->nr];
    for (int j = 0; j < sys_param->nr; ++j) {
      agg_key[i][j].init(sys_param->pairing);
    }
  }

  std::function<void(int&)> san_agg_key = [this, &agg_key](int& rank) {
    size_t agg_key_size = agg_key[rank][0].string_to_agg(NULL);
    char buf[agg_key_size * sys_param->nr];
    channel_sender[rank].receive(buf, agg_key_size * sys_param->nr);
  auto start = chrono::system_clock::now();
    San_Aggregate san_agg;
    san_agg.init(sys_param->pairing);
    element_t r1, r2;
    element_init_Zr(r1, sys_param->pairing);
    element_init_Zr(r2, sys_param->pairing);
    element_t temp, temp2, temp3;
    element_init_G1(temp, sys_param->pairing);
    element_init_G1(temp2, sys_param->pairing);
    element_init_Zr(temp3, sys_param->pairing);
    for (int i = 0; i < sys_param->nr; ++i) {
      agg_key[rank][i].string_to_agg(buf + i * agg_key_size);
      element_random(r1);
      element_random(r2);
      element_pow_zn(temp, agg_key[rank][i].h0, r1);
      element_pow_zn(temp2, sys_param->gm1[0], r2);
      element_mul(san_agg.d0, temp, temp2);
      element_mul(san_agg.d0, san_agg.d0, agg_key[rank][i].h2);
      element_pow_zn(san_agg.d0, san_agg.d0, RK2[rank]);
      mpz_t temp_mpz;
      mpz_init_set_ui(temp_mpz, rank);
      element_pow_mpz(temp3, RK1[i], temp_mpz);
      element_neg(temp3, temp3);
      element_pow_zn(temp, sys_param->gm1[0], temp3);
      element_mul(temp, temp, agg_key[rank][i].h1);
      element_pow_zn(temp, temp, r1);
      element_mul(san_agg.d1, temp, agg_key[rank][i].h3);
      element_pow_zn(temp, pkr[i], r2);
      element_mul(san_agg.d1, san_agg.d1, temp);
      element_pow_zn(san_agg.d1, san_agg.d1, RK2[rank]);
      mpz_clear(temp_mpz);
      size_t san_agg_size = san_agg.to_string(NULL);
      char buf_san_agg[san_agg_size];
      san_agg.to_string(buf_san_agg);
      channel_receiver[i].send(buf_san_agg, san_agg_size);
    }
    element_clear(temp);
    element_clear(temp2);
    element_clear(temp3);
    element_clear(r1);
    element_clear(r2);
  auto end = chrono::system_clock::now();
  chrono::duration<double> time_san = end - start;
  cout << "san time " << GREEN << time_san.count() << WHITE << " s" << endl;
  cout << "------------------------------------------" << endl;
  };
  for (int i = 0; i < sys_param->ns; ++i) {
    san_agg_key(i);
  }
  for (int i = 0; i < sys_param->ns; ++i) {
    delete[] agg_key[i];
  }
  delete[] agg_key;
}