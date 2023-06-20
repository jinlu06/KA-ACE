#include "util.h"

#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
using namespace std;
void Params::init(int ns_, int nr_, int m_, Entity entity) {
  const char* file_name = "ul/f.param";
  auto start_set = chrono::system_clock::now();
  fstream fp(file_name);
  fp.seekg(0, std::ios::end);
  int count = fp.tellg();
  fp.seekg(0, std::ios::beg);
  char* param = new char[count];
  fp.read(param, count);
  fp.close();
  pairing_init_set_buf(pairing, param, count);
  delete[] param;
  ns = ns_;
  nr = nr_;
  m = m_;
  // g1, g2, gm1, gm2
  gm1 = new element_t[(m * 2) + 1];
  gm2 = new element_t[(m * 2) + 1];
  if (entity == trusted_authority) {
    element_t a, ahat;
    element_init_G1(gm1[0], pairing);  // g_1
    element_random(gm1[0]);
    element_init_G2(gm2[0], pairing);  // g_2
    element_random(gm2[0]);
    // a, l
    element_init_Zr(a, pairing);
    element_random(a);
    element_init_Zr(ahat, pairing);
    // gm
    for (int i = 1; i < 2 * m + 1; i++) {
      element_init_G1(gm1[i], pairing);
      element_init_G2(gm2[i], pairing);
      if (i != m + 1) {
        mpz_t temp;
        mpz_init_set_ui(temp, i);
        element_pow_mpz(ahat, a, temp);  // ahat = a ^ i
        element_pow_zn(gm1[i], gm1[0], ahat);
        element_pow_zn(gm2[i], gm2[0], ahat);
        mpz_clear(temp);
      } else
        continue;
    }
    element_clear(ahat);
    element_clear(a);
    // set access control policy
    set_P();
    // msk
    alpha = new element_t[nr];
    beta = new element_t[ns];
    for (int i = 0; i < nr; i++) {
      element_init_Zr(alpha[i], pairing);
      element_random(alpha[i]);
    }
    for (int i = 0; i < ns; i++) {
      element_init_Zr(beta[i], pairing);
      element_random(beta[i]);
    }
  } else {
    element_init_G1(gm1[0], pairing);  // g_1
    element_init_G2(gm2[0], pairing);  // g_2
    // gm
    for (int i = 1; i < 2 * m + 1; i++) {
      element_init_G1(gm1[i], pairing);
      element_init_G2(gm2[i], pairing);
    }
    if (entity == sender || entity == receiver) set_sij();
    alpha = nullptr;
    beta = nullptr;
    if (entity == receiver) set_P();
  }
  auto end_set = chrono::system_clock::now();
  chrono::duration<double> time_set = end_set - start_set;
  cout << entity << " setup generte time " << GREEN << time_set.count() << WHITE
       << " s" << endl;
  cout << "------------------------------------------" << endl;
}

Params::~Params() {
  if (gm1 != nullptr || gm2 != nullptr) {
    for (int i = 0; i < 2 * m + 1; i++) {
      element_clear(gm1[i]);
      element_clear(gm2[i]);
    }
    delete[] gm1;
    delete[] gm2;
  }
  if (alpha != nullptr) {
    for (int i = 0; i < ns; i++) {
      element_clear(beta[i]);
    }
    for (int i = 0; i < nr; i++) {
      element_clear(alpha[i]);
    }
    delete[] alpha;
    delete[] beta;
  }
  pairing_clear(pairing);
}

size_t Params::to_string(char* buf) {
  if (buf == NULL) return 2 * (2 * m + 1) * ELEMENT_SIZE;
  for (int i = 0; i < (2 * m + 1); i++) {
    element_snprint(buf + i * ELEMENT_SIZE, ELEMENT_SIZE, gm1[i]);
    element_snprint(buf + (2 * m + 1 + i) * ELEMENT_SIZE, ELEMENT_SIZE, gm2[i]);
  }
  return 2 * (2 * m + 1) * ELEMENT_SIZE;
}

size_t Params::string_to_param(char* buf) {
  if (buf == NULL) return 2 * (2 * m + 1) * ELEMENT_SIZE;
  for (int i = 0; i < (2 * m + 1); i++) {
    element_set_str(gm1[i], buf + i * ELEMENT_SIZE, 0);
    element_set_str(gm2[i], buf + (2 * m + 1 + i) * ELEMENT_SIZE, 0);
  }
  return 2 * (2 * m + 1) * ELEMENT_SIZE;
}

// 0 -> 0
// 1 -> 0, 1
// 2 -> 0, 1, 2
void Params::set_P() {
  P.resize(ns, vector<bool>(nr));
  for (int i = 0; i < ns; ++i) {
    for (int j = 0; j < nr; ++j)
      if (j < nr / 2)
        P[i][j] = true;
      else
        P[i][j] = false;
  }
}

void Params::set_sij() {
  for (size_t i = 0; i < m; ++i) {
    sij.push_back(i + 1);
  }
}

void Plain::init(pairing_t& pairing) { element_init_GT(M, pairing); }

void Plain::set(int m, int data) {
  num = m;
  element_set_si(M, data);
}

Plain::~Plain() { element_clear(M); }

void Cipher::init(pairing_t& pairing) {
  element_init_G2(c0, pairing);
  element_init_G2(c1, pairing);
  element_init_GT(c2, pairing);
}

void Cipher::set(int m) { num = m; }

size_t Cipher::to_string(char* buf) {
  if (buf == NULL) return 3 * ELEMENT_SIZE;
  element_snprint(buf, ELEMENT_SIZE, c0);
  element_snprint(buf + ELEMENT_SIZE, ELEMENT_SIZE, c1);
  element_snprint(buf + 2 * ELEMENT_SIZE, ELEMENT_SIZE, c2);
  return 3 * ELEMENT_SIZE;
}
size_t Cipher::string_to_cipher(char* buf) {
  if (buf == NULL) return 3 * ELEMENT_SIZE;
  element_set_str(c0, buf, 0);
  element_set_str(c1, buf + ELEMENT_SIZE, 0);
  element_set_str(c2, buf + 2 * ELEMENT_SIZE, 0);
  return 3 * ELEMENT_SIZE;
}

Cipher::~Cipher() {
  element_clear(c0);
  element_clear(c1);
  element_clear(c2);
}

void Aggregate_key::init(pairing_t& pairing) {
  element_init_G1(h0, pairing);
  element_init_G1(h1, pairing);
  element_init_G1(h2, pairing);
  element_init_G1(h3, pairing);
}

void Aggregate_key::random() {
  element_random(h0);
  element_random(h1);
  element_random(h2);
  element_random(h3);
}

size_t Aggregate_key::to_string(char* buf) {
  if (buf == NULL) return 4 * ELEMENT_SIZE;
  element_snprint(buf, ELEMENT_SIZE, h0);
  element_snprint(buf + ELEMENT_SIZE, ELEMENT_SIZE, h1);
  element_snprint(buf + 2 * ELEMENT_SIZE, ELEMENT_SIZE, h2);
  element_snprint(buf + 3 * ELEMENT_SIZE, ELEMENT_SIZE, h3);
  return 4 * ELEMENT_SIZE;
}
size_t Aggregate_key::string_to_agg(char* buf) {
  if (buf == NULL) return 4 * ELEMENT_SIZE;
  element_set_str(h0, buf, 0);
  element_set_str(h1, buf + ELEMENT_SIZE, 0);
  element_set_str(h2, buf + 2 * ELEMENT_SIZE, 0);
  element_set_str(h3, buf + 3 * ELEMENT_SIZE, 0);
  return 4 * ELEMENT_SIZE;
}

Aggregate_key::~Aggregate_key() {
  element_clear(h0);
  element_clear(h1);
  element_clear(h2);
  element_clear(h3);
}

void San_Aggregate::init(pairing_t& pairing) {
  element_init_G1(d0, pairing);
  element_init_G1(d1, pairing);
}

size_t San_Aggregate::to_string(char* buf) {
  if (buf == NULL) return 2 * ELEMENT_SIZE;
  element_snprint(buf, ELEMENT_SIZE, d0);
  element_snprint(buf + ELEMENT_SIZE, ELEMENT_SIZE, d1);
  return 2 * ELEMENT_SIZE;
}
size_t San_Aggregate::string_to_agg(char* buf) {
  if (buf == NULL) return 2 * ELEMENT_SIZE;
  element_set_str(d0, buf, 0);
  element_set_str(d1, buf + ELEMENT_SIZE, 0);
  return 2 * ELEMENT_SIZE;
}

San_Aggregate::~San_Aggregate() {
  element_clear(d0);
  element_clear(d1);
}
