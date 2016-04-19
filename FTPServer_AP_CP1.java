package nsproject;

import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

public class FTPserver_AP_CP1 {
    public static void main(String[] args) throws Exception {
        // initiate the server socket
        ServerSocket serverSocket = new ServerSocket(43211);

        // handshake
        Socket clientSocket = serverSocket.accept();
        System.out.println("client connected");  

        InputStream inputStream_from_client = clientSocket.getInputStream();   
        InputStreamReader isr = new InputStreamReader(inputStream_from_client);
        BufferedReader in = new BufferedReader(isr);
        OutputStream outputStream_to_client = clientSocket.getOutputStream();         
        PrintWriter out = new PrintWriter(outputStream_to_client, true);

        // receive plain nonce broadcasted by client
        String nonce = in.readLine();
        System.out.println("nonce received: "+nonce);

        // generate private key
        String privateKeyFileName = "C:\\Users\\zhexian\\Dropbox\\VM\\NSProjectRelease\\"+
        "RSA certificate request\\privateServer.der";
        Path path = Paths.get(privateKeyFileName);
        byte[] privKeyByteArray = Files.readAllBytes(path);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey server_privateKey = keyFactory.generatePrivate(keySpec);

        // encrypt nonce with private key
        Cipher rsaCipher_encrypt_nonce= Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher_encrypt_nonce.init(Cipher.ENCRYPT_MODE, server_privateKey);
        byte[] encrypted_nonce= rsaCipher_encrypt_nonce.doFinal((nonce.getBytes()));
        
        // convert encrypted nonce into String (base64binary)
        String encrypted_nonce_string = DatatypeConverter.printBase64Binary(encrypted_nonce);
        System.out.println("encrypt nounce: "+encrypted_nonce_string);
        System.out.println("encrypt nounce size: "+encrypted_nonce.length);

        // send encrypted nonce to client
        out.write(encrypted_nonce_string+"\n");
        out.flush();
        System.out.println("encrypt nonce sent");

        // read file transfered from client, write acknowledgement to client
        String fileReceived = in.readLine();
        out.write("uploaded file\n");
        out.flush();

        // convert String received from client (encrypted file) to byte[]
        byte[] fileReceived_byte = DatatypeConverter.parseBase64Binary(fileReceived);

        // decrypt the encrypted file in byte[] format useing private key
        Cipher rsaCipher_decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher_decrypt.init(Cipher.DECRYPT_MODE, server_privateKey);

        //TODO: break up bytes into <117= 100 per block to do final
        int file_byte_length= fileReceived_byte.length;
        int number_of_blocks= (int) Math.ceil(file_byte_length/100.0);
        //e.g. 350: get 3: index from 0 to 3
        //encrypt message
        byte[][] blocks_of_fileBytes= new byte[number_of_blocks][];
        byte[][] blocks_of_decryptedBytes= new byte[number_of_blocks][];

        for (int i=0; i<blocks_of_fileBytes.length; i+=100) {
            blocks_of_fileBytes[i]= Arrays.copyOfRange(fileReceived_byte, i, i + 100);
        }
        for (int i=0; i<blocks_of_fileBytes.length; i+=100) {
            blocks_of_decryptedBytes[i]= rsaCipher_decrypt.doFinal(blocks_of_fileBytes[i]);
        }
        //TODO: concantenate byte array using ByteArrayOutputStream
        ByteArrayOutputStream joining_decrypted_blocks= new ByteArrayOutputStream();

        for (byte[] block: blocks_of_decryptedBytes) {
            joining_decrypted_blocks.write(block, 0, block.length);
        }
        byte[] decryptedBytes= joining_decrypted_blocks.toByteArray();
        //TODO: END OF CHANGE
        //byte[] decryptedBytes = rsaCipher_decrypt.doFinal(fileReceived_byte);
        //----------ask TA: arrayOutOfBoundException here-------------

        // create a new file to store ht file received from client
        File file = new File("FTP1.txt");
        FileWriter writer = new FileWriter(file);
        writer.write(new String(decryptedBytes));
        writer.close();

        // create a separate thread for the FTP client

        //FTPthread ftpThread = new FTPthread(inChannel, outChannel);

        // starting the thread
        
        //ftpThread.start();

        // join thread
        //try {
            
        //     ftpThread.join();

        // } catch (InterruptedException e) {
        //     System.out.println("A thread didn't finish!");
        // } catch (Exception e) {
        //     System.out.println("Exception captured.");
        // }

        // System.out.println("File has been successfully transferred!");             

        // System.out.println("Server connection terminated");   
        // serverSocket.close();
    }
}

// Thread class
// class FTPthread extends Thread {
//     private BufferedReader in;
//     private PrintWriter out;
    
//     public FTPthread (BufferedReader in, PrintWriter out) {
//         this.in = in;
//         this.out = out;
//     }
    
//     public void run () {
//         // TODO: create bytes object instead of text file
//         File file = new File("client " + id + " file.txt");
//         BufferedWriter output;
//         try {
//             // output = new BufferedWriter(new FileWriter(file));
//             String newLine = in.readLine();
//             while(newLine!=null){
//                 // output.write(newLine);
//                 // out.println("Received");
//                 // out.flush();
//                 newLine = in.readLine();
//                 //TODO: add the in readline to the file saved
//             }
//             // TODO: compare the hash to check message integrity
//             output.close();  
//         } catch (IOException e) {
//             e.printStackTrace();
//         }
//     }
// }