# KA-ACE

## Introduction
Key-Aggregate Based Access Control Encryption for Flexible Cloud Data Sharing

## Build

### Compile
ul: make ul
udl: make udl
### Clean
make clean
### Environmental requirement
install the pbc library
## Use
The following takes the ul scheme as an example to show how to use it, and and the same for the udl scheme.

Open three terminals, where the first terminal represents TrustedAuthority, Server, Sanitizer, the second terminal represents ns senders, and the third terminal represents nr receivers.
* first terminal: ./output/ul 3 3 100 0
* second terminal: ./output/ul 3 3 100 1
* third terminal: ./output/ul 3 3 100 2

argv[0] denotes test program. argv[1] denotes the number of senders, argv[2] denotes the number of receivers, argv[3] denotes the number of files, argv[4] denotes parties, where 0 represents TrustedAuthority, Server, Sanitizer, 1 represents sender, and 2 represents receiver.

* After running, the result is as follows：

```html
first terminal:
San start 
server start 
TrustedAuthority start 
4 setup generte time 0.283254 s
2 setup generte time 0.251832 s
0 setup generte time 0.735153 s
keygen time 0.0192421 s
san time 0.0302618 s
san time 0.0322107 s
san time 0.0271347 s
------------------------------------------
second terminal:
Sender start 
Sender start 
Sender start 
1 setup generte time 0.348683 s
1 setup generte time 0.32027 s
1 setup generte time 0.281659 s
enc time 11.7762 s
enc time 11.8007 s
extract time 0.0314332 s
enc time 11.8304 s
extract time 0.0203717 s
extract time 0.0216451 s
------------------------------------------
third terminal:
Receiver start 
Receiver start 
Receiver start 
3 setup generte time 0.29402 s
3 setup generte time 0.280316 s
3 setup generte time 0.247395 s
sender 0can't comm with receiver 1
sender 1can't comm with receiver 1
sender 2can't comm with receiver 1
sender 0can't comm with receiver 2
sender 1can't comm with receiver 2
sender 2can't comm with receiver 2
dec time 5.7287 s
dec time 6.35391 s
dec time 6.3745 s

```

## Notice
The access control policy can be accessed by modifying the utils.cpp:128, the access policy is now an upper triangle, i.e

0 -> 0

1 -> 0 1

2 -> 0, 1, 2