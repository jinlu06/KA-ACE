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
  // sender pk
  char buf_pk_sender[sys_param->ns * ELEMENT_SIZE * 2];
  channel_ta->receive(buf_pk_sender, sys_param->ns * ELEMENT_SIZE * 2);
  pks1 = new element_t[sys_param->ns];
  pks2 = new element_t[sys_param->ns];
  for (int i = 0; i < sys_param->ns; i++) {
    element_init_G1(pks1[i], sys_param->pairing);
    element_init_G2(pks2[i], sys_param->pairing);
    element_set_str(pks1[i], buf_pk_sender + i * ELEMENT_SIZE * 2, 0);
    element_set_str(pks2[i],
                    buf_pk_sender + i * ELEMENT_SIZE * 2 + ELEMENT_SIZE, 0);
  }
  // receiver pk
  char buf_pk[sys_param->nr * ELEMENT_SIZE];
  channel_ta->receive(buf_pk, sys_param->nr * ELEMENT_SIZE);
  pkr = new element_t[sys_param->nr];
  for (int i = 0; i < sys_param->nr; ++i) {
    element_init_G1(pkr[i], sys_param->pairing);
    element_set_str(pkr[i], buf_pk + i * ELEMENT_SIZE, 0);
  }
  // RK
  RK = new element_t*[sys_param->ns];
  char buf_rk[sys_param->ns * sys_param->nr * ELEMENT_SIZE];
  channel_ta->receive(buf_rk, sys_param->ns * sys_param->nr * ELEMENT_SIZE);
  for (int i = 0; i < sys_param->ns; ++i) {
    RK[i] = new element_t[sys_param->nr];
    for (int j = 0; j < sys_param->nr; ++j) {
      element_init_G1(RK[i][j], sys_param->pairing);
      element_set_str(RK[i][j], buf_rk + (i * sys_param->nr + j) * ELEMENT_SIZE,
                      0);
    }
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
  if (RK != nullptr) {
    for (int i = 0; i < sys_param->ns; ++i) {
      for (int j = 0; j < sys_param->nr; ++j) {
        element_clear(RK[i][j]);
      }
      delete[] RK[i];
    }
    delete[] RK;
  }
  if (pkr != nullptr) {
    for (int j = 0; j < sys_param->nr; ++j) {
      element_clear(pkr[j]);
    }
    delete[] pkr;
  }
  if (pks1 != nullptr) {
    for (int j = 0; j < sys_param->ns; ++j) {
      element_clear(pks1[j]);
      element_clear(pks2[j]);
    }
    delete[] pks1;
    delete[] pks2;
  }
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
    bool res = true;
    element_t left, right, tmp;
    element_init_GT(left, sys_param->pairing);
    element_init_GT(right, sys_param->pairing);
    element_init_GT(tmp, sys_param->pairing);
    element_t r;
    element_init_Zr(r, sys_param->pairing);
    San_Aggregate san_agg;
    san_agg.init(sys_param->pairing);
    for (int j = 0; j < sys_param->nr; ++j) {
      agg_key[rank][j].string_to_agg(buf + j * agg_key_size);
      // check
      element_pairing(left, agg_key[rank][j].h1, agg_key[rank][j].h2);
      element_pairing(right, RK[rank][j], agg_key[rank][j].h3);
      element_pairing(tmp, pkr[j], agg_key[rank][j].h4);

      element_mul(right, right, tmp);
      if (element_cmp(right, left)) {
        res = false;
        std::cout << "verify1 fail" << std::endl;
        channel_receiver[j].send(&res, sizeof(bool));
        continue;
      }
      element_pairing(left, sys_param->gm1[0], agg_key[rank][j].h3);
      element_pairing(right, pks1[rank], sys_param->v);
      if (element_cmp(right, left)) {
        res = false;
        std::cout << "verify2 fail" << std::endl;
        channel_receiver[j].send(&res, sizeof(bool));
        continue;
      }
      element_pairing(left, agg_key[rank][j].h0, agg_key[rank][j].h2);
      element_pairing(right, sys_param->gm1[0], agg_key[rank][j].h4);
      if (element_cmp(right, left)) {
        res = false;
        std::cout << "verify3 fail" << std::endl;
        channel_receiver[j].send(&res, sizeof(bool));
        continue;
      }
      channel_receiver[j].send(&res, sizeof(bool));
      // san
      size_t san_agg_size = san_agg.to_string(NULL);
      char buf_san_agg[san_agg_size];
      element_random(r);
      element_t tmp2;
      element_init_G1(tmp2, sys_param->pairing);
      element_pow_zn(tmp2, sys_param->gm1[0], r);
      element_mul(san_agg.d0, agg_key[rank][j].h0, tmp2);
      element_pow_zn(tmp2, pkr[j], r);
      element_mul(san_agg.d1, agg_key[rank][j].h1, tmp2);
      san_agg.to_string(buf_san_agg);
      channel_receiver[j].send(buf_san_agg, san_agg_size);
      element_clear(tmp2);
    }
    element_clear(tmp);
    element_clear(r);
    element_clear(left);
    element_clear(right);
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