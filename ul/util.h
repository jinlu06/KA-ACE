#ifndef __UTIL_H__
#define __UTIL_H__
#include <pbc.h>

#include <chrono>
#include <functional>
#include <iostream>
#include <string>
#include <vector>

#define RESET   "\033[0m"
#define BLACK   "\033[30m"      /* Black */
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */
#define BLUE    "\033[34m"      /* Blue */
#define WHITE   "\033[37m"      /* White */

#define ELEMENT_SIZE 650  // GT data size
#define DEFPORT 5001
#define SERPORT 6001
#define SANPORT 7001
#define DEFIP "127.0.0.1"
enum Entity {
  trusted_authority = 0,
  sender = 1,
  sanitizer = 2,
  receiver = 3,
  cloud_server = 4
};

class Params {
 public:
  Params(){};
  void init(int ns_, int nr_, int m_, Entity entity);
  ~Params();
  size_t to_string(char* buf);
  size_t string_to_param(char* buf);
  void set_P();
  void set_sij();

 public:
  pairing_t pairing;
  element_t* gm1;                    // g1 = gm1[0]
  element_t* gm2;                    // g2 = gm2[0]
  int ns;                             // sender
  int nr;                             // receiver number
  int m;                             // file class number
  element_t* alpha;                  // n
  element_t* beta;                   // n
  std::vector<std::vector<bool>> P;  // n * n
  std::vector<size_t> sij;
};

class Plain {
 public:
  element_t M;
  int num;  // 第 n 类文件
 public:
  Plain() {}
  void init(pairing_t& pairing);
  void set(int m, int data);
  ~Plain();
};

class Cipher {
 public:
  element_t c0;
  element_t c1;
  element_t c2;
  int num;

 public:
  Cipher() {}
  void init(pairing_t& pairing);
  void set(int m);
  ~Cipher();
  size_t to_string(char* buf);
  size_t string_to_cipher(char* buf);
};

class Aggregate_key {
 public:
  element_t h0;
  element_t h1;
  element_t h2;
  element_t h3;

 public:
  Aggregate_key(){};
  void random();
  ~Aggregate_key();
  void init(pairing_t& pairing);
  size_t to_string(char* buf);
  size_t string_to_agg(char* buf);
};

class San_Aggregate {
 public:
  element_t d0;
  element_t d1;

 public:
  San_Aggregate(){};
  ~San_Aggregate();
  void init(pairing_t& pairing);
  size_t to_string(char* buf);
  size_t string_to_agg(char* buf);
};
#endif