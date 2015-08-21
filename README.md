# iso9797algorithm3
Research implementation of iso 9797 algorithm 3 in C.

I first published this on one of my blogs in 2010.

http://devinvenable.blogspot.com/2010/01/iso-9797-algorithm-3.html

Last Friday I set out to implement ISO 9797 algorithm 3 using the OpenSSL library. I did not have the specification handy, so I decided to to the best I could with what I could find by way of examples on the net.


I came across a description of the algorithm in this 2005 thread (http://www.derkeiler.com/Newsgroups/sci.crypt/2005-02/0374.html). This was posted in a query by someone named Christian. He also posted his keys, data and the expected answer.


H0 = 0
stages 1 to n: Hj = Enc(K, Dj XOR H{j-1})
MAC = Enc(K, Dec(K', Hn))


Francois Grieu replied with, "This is very likely ISO/IEC 9797-1, using DES as the block cipher,
padding method 2, MAC algorithm 3." He provided an answer by sharing sample code in "some near-extinct dialect".


set m0 72C29C2371CC9BDB #message
set m1 65B779B8E8D37B29
set m2 ECC154AA56A8799F
set m3 AE2F498F76ED92F2

set pd 8000000000000000 #padding

set iv 0000000000000000 #initialisation vector

set k0 7962D9ECE03D1ACD #key
set k1 4C76089DCE131543

set xx {iv} # setup
for mj in {m0} {m1} {m2} {m3} {pd} # for each block including padding
     set xx `xor {xx} {mj}` # chain
      set xx `des -k {k0} -c {xx}` #encrypt
      end
      set xx `des -k {k1} -d {xx}` #decrypt
      set xx `des -k {k0} -c {xx}` #encrypt
      echo {xx} #show result

      5F1448EEA8AD90A7 


I've implemented the same in c for the purpose of research. 

