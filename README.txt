CPSC452 Assignment3

Name: Roberto Perez Mendoza
Email: perezmendoza_roberto@csu.fullerton.edu

Programming language used: Python 2.7

How to execute: The program can be executed by openning the terminal and looking
for the directory "p3_rperezmendoza1" Once accessed to the directory, one should
type the following: python ./signer.py <KEY FILE NAME> <SIGNATURE FILE name> <INPUT FILE NAME> <MODE>
As an example to what I did was: roberto@roberto-VirtualBox:~/Desktop/p3_rperezmendoza1$ python ./signer.py pubKey.pem music.sig music.mp3 verify

Extra credit: Extra credit was implemented. For this portion, the <MODE> must use
either <sign-aes/verify-aes> Example: roberto@roberto-VirtualBox:~/Desktop/p3_rperezmendoza1$ python ./signer.py privKey.pem 0123456789abcdef012223456789cdef music.mp3 sign-aes
When doing pubKey, for the <INPUT FILE> you must enter the created file e.g. enc_music.mp3

Anything special: Please, be aware that the patameters to execution this program is in lower
case. It is case sensitive. Meaning that if upper case is included, it won't work.
