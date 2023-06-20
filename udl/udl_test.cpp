#include "receiver.h"
#include "trusted_authority.h"
#include "sanitizer.h"
#include "sender.h"
#include "server.h"
#include "util.h"
#include <stdlib.h>
#include <future>
using namespace std;

void TrustedAuthorityStart(int ns, int nr, int m) {
    std::cout << GREEN << "TrustedAuthority start " << WHITE<< std::endl;
    Entity e = trusted_authority;
    TrustedAuthority TA(ns, nr, m, e);
}

void ServerStart(int ns, int nr, int m) {
    std::cout << GREEN << "server start " << WHITE<< std::endl;
    Entity e = cloud_server;
    Server serv(ns, nr, m, e);
    serv.get_data();
    serv.data_to_receiver();
}

void SenderStart(int ns, int nr, int m, int rank) {
    std::cout << GREEN << "Sender start " << WHITE<< std::endl;
    Entity e = sender;
    Sender sender(ns, nr, m, e, rank);
    sender.encrypt();
    sender.extract();
}

void ReceiverStart(int ns, int nr, int m, int rank) {
    std::cout << GREEN << "Receiver start " << WHITE<< std::endl;
    Entity e = receiver;
    Receiver receiver(ns, nr, m, e, rank);
    receiver.decrypt();
}

void SanStart(int ns, int nr, int m) {
    std::cout << GREEN << "San start " << WHITE<< std::endl;
    Entity e = sanitizer;
    Sanitizer san(ns, nr, m, e);
    san.san();
}

int main(int argc, char **argv) {
    int ns = atoi(argv[1]);
    int nr = atoi(argv[2]);
    int m = atoi(argv[3]);
    // three terminal
    int tt = atoi(argv[4]);
    if (tt == 0) {
        std::thread t1(TrustedAuthorityStart, ns, nr, m);
        std::thread t2(ServerStart, ns, nr, m);
        std::thread t3(SanStart, ns, nr, m);
        t1.join();
        t2.join();
        t3.join();
    } else if (tt == 1) {
        std::vector<thread> sender_t;
        for (int i = 0; i < ns; ++i) {
            sender_t.push_back(thread(SenderStart, ns, nr, m, i));
        }
        for (int i = 0; i < ns; ++i) {
            sender_t[i].join();
        }
    } else if (tt == 2) {
        std::vector<thread> receiver_t;
        for (int i = 0; i < nr; ++i) {
            receiver_t.push_back(std::thread(ReceiverStart, ns, nr, m, i));
        }
        for (int i = 0; i < nr; ++i) {
            receiver_t[i].join();
        }
    }

    // // signal termial
    // std::thread t1(TrustedAuthorityStart, n, m);
    // std::thread t2(ServerStart, n, m);
    // std::thread t3(SanStart, n, m);

    // std::vector<thread> sender_t;
    // for (int i = 0; i < n; ++i) {
    //   sender_t.push_back(thread(SenderStart, n, m, i));
    // }

    // std::vector<thread> receiver_t;
    // for (int i = 0; i < n; ++i) {
    //   receiver_t.push_back(std::thread(ReceiverStart, n, m, i));
    // }
    // t1.join();
    // t2.join();
    // t3.join();
    // for (int i = 0; i < n; ++i) {
    //   sender_t[i].join();
    // }
    // for (int i = 0; i < n; ++i) {
    //   receiver_t[i].join();
    // }
    return 0;
}