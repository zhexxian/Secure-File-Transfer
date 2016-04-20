/* Programming Assignment 2 
* Author : Valerie Tan, Zhang Zhexian
* ID : *******, 1001214 
* Date : 20/04/2016 */

CONTENTS OF THIS FILE
---------------------
   
* Introduction
* Features
* Instructions


INTRODUCTION
------------

The Secure File Transfer program is an automated program for easy and
secure file transfer between different machines (ports). It allows client
to transfer a file specified by its file name to be received stored by
a verified server.

FEATURES
-------

* Authentication (CA)

Authentication of the server is verified in the following three steps:

1. Checking the validity of the certification agency (CA)'s certificate
2. Checking the validity of the server's certificate
3. Verifying the server's certificate using the CA's public key

* Authentication (nonce)

To prevent the playback attack, a nonce is sent by the client, encrypted
by the server using its private key, and decrypted by the client using
the server's public key to verify that the server is indeed the intended
server. The nonce is unique for each connection.

* Confidentiality (CP1: RSA; CP2: RSA+AES)

For CP1, the message is fully encrypted by RSA using server's public key;
For CP2, a unique symmetrical session key (AES) is encrypted by RSA using
the server's public key, and the message itself is encrypted by the AES
key to increase file transfer efficiency.


INSTRUCTIONS
-----------

To use the program, the server and client are running on different machines.

Following are the instructions for the server and client respectively:

***For server:

* Step 1: Specify port number in line 27,
	  by changing replacing 4321 with your own number, or leave it as it
	  is in ServerSocket serverSocket = new ServerSocket(4321);

* Step 2: Locate the certificate, by changing the directory in line 46:
	  String fileName = "your//directory";

* Step 3: Locate the private key, by changing the directory in line 85:
	  String privateKeyFileName = "your//directory";

* Step 4: Specify the name of the file to be saved, by changing the file
	  name in line 158 (for CP1) and line 142 (for CP2).

* Step 5: Run the server program (do this before running client)

***For client:

* Step 1: Specify server's IP address and port number in line 49-50;

* Step 2: Change the nonce in line 52 if needed;

* Step 3: Locate the CA cert, by changing the directory in line 83:
	  InputStream caCertInputStream= new FileInputStream("your//directory");

* Step 4: Specify the root folder of the file to be transferred in line 174;

* Step 5: Run the client program

* Step 6: When prompted by "enter the name of the file to be transferred: ", 
	  key in the file name with extension, followed by pressing 'enter' key
	  
	  