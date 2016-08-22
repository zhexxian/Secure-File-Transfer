Secure File Transfer
====================

The Secure File Transfer program is an automated program for easy and
secure file transfer between different machines (ports). It allows the client
to transfer a file, specified by its file name, to be received and stored by
a verified server.

[TOC]

Features
========

Authentication (CA)
-------------------

Authentication of the server is verified in the following three steps:

 - Checking the validity of the certification agency (CA)'s certificate 
 - Checking the validity of the server's certificate
 - Verifying the server's certificate using the CA's public key


Authentication (nonce)
----------------------

To prevent the playback attack, a nonce is sent by the client, encrypted
by the server using its private key, and decrypted by the client using
the server's public key to verify that the server is indeed the intended
server. The nonce is unique for each connection.


Confidentiality (CP1: RSA; CP2: RSA+AES)
----------------------------------------

For CP1, the message is fully encrypted by RSA using server's public key;
For CP2, a unique symmetrical session key (AES) is encrypted by RSA using
the server's public key, and the message itself is encrypted by the AES
key to increase file transfer efficiency.


Instructions
=======

To use the program, the server and client are running on different machines.

Following are the instructions for the server and client respectively:

Server
-----------

 1. Specify port number in line 27, 	  by changing replacing ```4321``` with your own number, or leave it as it is in
    ```ServerSocket serverSocket = new ServerSocket(4321);```

 2. Locate the certificate, by changing the directory in line 46: ```String fileName = "your//directory";```

 3. Locate the private key, by changing the directory in line 85: ```String privateKeyFileName = "your//directory";```

 4. Specify the name of the file to be saved, by changing the file name in line 169 (for CP1) and line 149 (for CP2)

 5. Run the server program (do this before running client)

Client
----------

 1. Specify server's IP address and port number in line 49-50

 2. Change the nonce in line 52 if needed

 3. Locate the CA cert, by changing the directory in line 83: ```InputStream caCertInputStream= new FileInputStream("your//directory");```

 4. Specify the root folder of the file to be transferred in line 174;

 5. Run the client program

 6. When prompted by ``` "enter the name of the file to be transferred: "```,  key in the file name with extension, followed by pressing 'enter' key


> **Note:** This project is an assignment for [50.005 Computer Systems Engineering](https://istd.sutd.edu.sg/undergraduate/courses/50005-computer-system-engineering) 
