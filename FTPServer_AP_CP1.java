/* Programming Assignment 2 
* Author : Valerie Tan, Zhang Zhexian
* ID : 1001191, 1001214 
* Date : 20/04/2016 */


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
        //initiate the server socket
        ServerSocket serverSocket = new ServerSocket(43211);

        //handshake with client
        Socket clientSocket = serverSocket.accept();
        System.out.println("client connected");  

        //initiate IO
        InputStream inputStream_from_client = clientSocket.getInputStream();  
        InputStreamReader isr = new InputStreamReader(inputStream_from_client);
        BufferedReader in = new BufferedReader(isr);
        OutputStream outputStream_to_client = clientSocket.getOutputStream();         
        PrintWriter out = new PrintWriter(outputStream_to_client, true);




//---------------------------1. Authentication (CA)--------------------------------//

        //server send its own certificate to client
        String fileName = "C:\\Users\\zhexian\\Documents\\GitHub\\Encrypted_FTP_NSproject\\Signed Certificate - 1001214.crt";
        File file_to_client = new File(fileName);
        String data = "";
        String line;
        BufferedReader bufferedReader = new BufferedReader(new FileReader(fileName));
        while ((line = bufferedReader.readLine()) != null) {
            data = data + "\n" + line;
        }

        FileInputStream fileInputStream = null;
        byte[] input_file_as_byte_array = new byte[(int) file_to_client.length()];
        int file_byte_length= input_file_as_byte_array.length;
        try {
            //convert file into byte array
            fileInputStream = new FileInputStream(file_to_client);
            fileInputStream.read(input_file_as_byte_array);
            fileInputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        //convert byte array file (server certificate) to base64 format
        String input_file_as_byte_array_string = DatatypeConverter.printBase64Binary(input_file_as_byte_array);

        //send cert to client
        out.write(input_file_as_byte_array_string+"\n");
        out.flush();
        System.out.println("server certificate sent");  




//---------------------------2. Authentication (nonce)--------------------------------//  

        // receive plain nonce broadcasted by client
        String nonce = in.readLine();
        System.out.println("plain nonce received: "+nonce);

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




//---------------------------3. Confidentiality (RSA)--------------------------------//

        //convert buffinputstream into byte array
        BufferedInputStream bufferedInputStream= new BufferedInputStream(inputStream_from_client);
        
        Integer numberBytes = new Integer(in.readLine());
        //initialize fileReceived_bytes
        byte[] fileReceived_byte = new byte[numberBytes];
        //then simply read over from stream into byte array
        bufferedInputStream.read(fileReceived_byte, 0, numberBytes);
        System.out.println("file received and read");


        // read file transfered from client, write acknowledgement to client
        // start time for file transfer
        long startTime = System.nanoTime();
        out.write("uploaded file\n");
        out.flush();

        // convert String received from client (encrypted file) to byte[]
        //byte[] fileReceived_byte = DatatypeConverter.parseBase64Binary(fileReceived);

        // decrypt the encrypted file in byte[] format useing private key
        Cipher rsaCipher_decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher_decrypt.init(Cipher.DECRYPT_MODE, server_privateKey);

        //break up bytes into 128 per block to do final(max)
        file_byte_length= fileReceived_byte.length;
        int number_of_blocks= (int) Math.ceil(file_byte_length/128.0);
        //e.g. 350: get 3: index from 0 to 3
        //encrypt message
        byte[][] blocks_of_fileBytes= new byte[number_of_blocks][];
        byte[][] blocks_of_decryptedBytes= new byte[number_of_blocks][];

        for (int i=0; i<blocks_of_fileBytes.length; i++) {
            //e.g. 1st block: copys 0th-100th byte from received file byte array
            if (i< blocks_of_fileBytes.length-1) {
                blocks_of_fileBytes[i] = Arrays.copyOfRange(fileReceived_byte, i * 128, (i + 1) * 128);
            }
            else{
                blocks_of_fileBytes[i] = Arrays.copyOfRange(fileReceived_byte, i * 128, fileReceived_byte.length);
            //e.g. 10th block( i= 9) has 70 bytes, we copy 900th byte to 970th byte(exclusive)
            }
        }
        for (int i=0; i<blocks_of_fileBytes.length; i++) {
            blocks_of_decryptedBytes[i]= rsaCipher_decrypt.doFinal(blocks_of_fileBytes[i]);
        }
        //concantenate byte array using ByteArrayOutputStream
        ByteArrayOutputStream joining_decrypted_blocks= new ByteArrayOutputStream();

        for (byte[] block: blocks_of_decryptedBytes) {
            joining_decrypted_blocks.write(block, 0, block.length);
        }
        byte[] decryptedBytes= joining_decrypted_blocks.toByteArray();
        //String decryptedFile_string = DatatypeConverter.printBase64Binary(decryptedBytes);


        //write decrypted bytes into a image file using FileOuputStream
        FileOutputStream create_image_file= new FileOutputStream("pathname for image.jpg");
        create_image_file.write(decryptedBytes);
        create_image_file.close();

        // end time for file transfer
        long endTime = System.nanoTime();
        long duration = (endTime - startTime); 
        // the time may include time to enter the name of the file to be transferred
        System.out.println("Time taken for file transfer [CP1] is: "+duration/1000000+" ms");                 
    }
}