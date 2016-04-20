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
import java.util.List;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class FTPserver_AP_CP2 {
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

        // server send its own certificate to client
        //send file (move in rest of code)
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
        System.out.println("server public key byte array length= "+ input_file_as_byte_array.length);
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

        //send file to client
        out.write(input_file_as_byte_array_string+"\n");
        out.flush();
        System.out.println("server certificate sent");    

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
        

        // read DES encrypted file from client
        String fileReceived = in.readLine();
        // start time for file transfer
        long startTime = System.nanoTime();
        // read encrypted DES session key from client, write acknowledgement to client
        String secrete_key_byte_encrypted_string = in.readLine();
        System.out.println(secrete_key_byte_encrypted_string);
        out.write("uploaded file\n");
        out.flush();

        // convert String received from client (encrypted file) to byte[]
        byte[] fileReceived_byte = DatatypeConverter.parseBase64Binary(fileReceived);
        byte[] secrete_key_byte_encrypted = DatatypeConverter.parseBase64Binary(secrete_key_byte_encrypted_string);

        // decrypt the encrypted DES session key in byte[] format useing private key
        Cipher rsaCipher_decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher_decrypt.init(Cipher.DECRYPT_MODE, server_privateKey);
        byte[] decryptedBytes = rsaCipher_decrypt.doFinal(secrete_key_byte_encrypted);
        SecretKey key = new SecretKeySpec(decryptedBytes, 0, decryptedBytes.length, "DES");

        //create cipher object, initialize the ciphers with the given key, choose decryption mode as DES
        Cipher cipher_decrypt = Cipher.getInstance("DES");
        cipher_decrypt.init(Cipher.DECRYPT_MODE, key); //init as decrypt mode

        //do decryption, by calling method Cipher.doFinal().
        byte[] decryptedFile = cipher_decrypt.doFinal(fileReceived_byte);
        //String decryptedFile_string = DatatypeConverter.printBase64Binary(decryptedFile);

        // create a new file to store ht file received from client
        File file = new File("FTP1.txt");
        FileWriter writer = new FileWriter(file);
        writer.write(new String(decryptedFile));
        writer.close();

        // end time for file transfer
        long endTime = System.nanoTime();
        long duration = (endTime - startTime); 
        // the time may include time to enter the name of the file to be transferred
        System.out.println("Time taken for file transfer [CP2] is: "+duration/1000000+" ms");          

        // System.out.println("Server connection terminated");   
        // serverSocket.close();
    }
}