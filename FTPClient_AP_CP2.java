/* Programming Assignment 2 
* Author : Valerie Tan, Zhang Zhexian
* ID : 1001191, 1001214 
* Date : 20/04/2016 */



package nsproject;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;
import javax.xml.bind.DatatypeConverter;

public class FTPClient_AP_CP2 {

    public static void main(String args[]) {

        String hostName = "10.12.22.161";
        int portNumber = 43211;
    
        String my_nonce = "kukuru";

        boolean file_sent = false;
        boolean upload_acknowledged = false;
     
        try {

            //handshake with server
            Socket clientSocket = new Socket(hostName, portNumber);

            //initiate IO
            InputStream inputStream_from_server = clientSocket.getInputStream();
            InputStreamReader isr = new InputStreamReader(inputStream_from_server);
            BufferedReader in = new BufferedReader(isr);
            OutputStream outputStream_to_server = clientSocket.getOutputStream();
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(),true);


//---------------------------1. Authentication (CA)--------------------------------//

            //receive certificate from server
            String serverCert_string = in.readLine();
            byte[] serverCert_byte = DatatypeConverter.parseBase64Binary(serverCert_string);

            //create a new file to store ht file received from client
            File file = new File("cert.crt");
            FileWriter writer = new FileWriter(file);
            writer.write(new String(serverCert_byte));
            writer.close();

            //create X509 Certificate object
            InputStream caCertInputStream= new FileInputStream("C:\\Users\\zhexian\\Documents\\GitHub\\Encrypted_FTP_NSproject\\CA.crt"); //TODO: REPLACE WITH ADDRESS
            CertificateFactory cf_ca= CertificateFactory.getInstance("X.509");
            X509Certificate CAcert= (X509Certificate) cf_ca.generateCertificate(caCertInputStream);

            try{
                CAcert.checkValidity();
                System.out.println("CA certificate valid");
            }catch (CertificateExpiredException e){
                e.printStackTrace();
            } catch (CertificateNotYetValidException e){
                e.printStackTrace();
            }

            // InputStream certFileInputStream = new FileInputStream("C:\\Users\\valer_000\\AndroidStudioProjects\\" +
            //         "CSE\\nslabs\\src\\main\\java\\nsproject\\Signed Certificate - 1001191.crt");
            // InputStream certFileInputStream = new FileInputStream("C:\\Users\\zhexian\\Dropbox\\VM\\NSProjectRelease\\"+
            //         "Signed Certificate - 1001214.crt\\Signed Certificate - 1001214.crt");
            InputStream certFileInputStream = new FileInputStream("cert.crt");
            CertificateFactory cf_myself = CertificateFactory.getInstance("X.509");
            X509Certificate MyCert = (X509Certificate) cf_myself.generateCertificate(certFileInputStream);
            
            //check validity of signed cert, if not valid an exception will be thrown
            try{
                MyCert.checkValidity();
                System.out.println("server certificate valid");
            }
            // CertificateExpiredException - if the certificate has expired.
            catch (CertificateExpiredException e){
                e.printStackTrace();
            }
            // CertificateNotYetValidException - if the certificate is not yet valid.
            catch (CertificateNotYetValidException e){
                e.printStackTrace();
            }

            //verify my cert using CA's public key
            PublicKey CA_Key = CAcert.getPublicKey();
            
            try {
                MyCert.verify(CA_Key);
            }catch (Exception e){
                e.printStackTrace();
            }
             
            //extract public key from X509 cert object
            PublicKey server_publicKey = MyCert.getPublicKey();



//---------------------------2. Authentication (nonce)--------------------------------// 

            //broadcast nonce (an int) to server (send without encryption)
            out.println(my_nonce);
            out.flush();
            System.out.println("plain nonce sent");

            //received encrypted nonce back from server
            String encrypted_nonce_string = in.readLine();
            System.out.println("encrypted nonce received: "+encrypted_nonce_string);

            //convert encrypted nonce to byte[] format
            byte[] encrypted_nonce = DatatypeConverter.parseBase64Binary(encrypted_nonce_string);
            
            //decrypt the nonce by creating RSA("RSA/ECB/PKCS1Padding") cipher object 
            //and initialize is as decrypt mode, use PUBLIC key
            Cipher rsaCipher_decrypt_nonce= Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher_decrypt_nonce.init(Cipher.DECRYPT_MODE, server_publicKey);
            byte[] decrypted_nonce= rsaCipher_decrypt_nonce.doFinal(encrypted_nonce);
            System.out.println("decrypted_nonce: "+decrypted_nonce);

            //convert byte[] into String and check if matches the original nonce
            String decrypted_nonce_string= new String(decrypted_nonce);
            if(decrypted_nonce_string.equals(my_nonce)){
                System.out.println("nonce matched");
            }




//---------------------------3. Confidentiality (RSA+AES)--------------------------------//

            //check that server acknowledged file upload, print and close connection
            //use a do-while loop (send file, receive acknowledgment, close connection)
            do{
                if(!file_sent){
                    //enter file name
                    System.out.println("enter the name of the file to be transferred: ");
                    BufferedReader stdIn =
                        new BufferedReader(
                            new InputStreamReader(System.in));
                    String inputFileName = stdIn.readLine();
                    String fileName = "C:\\Users\\zhexian\\Dropbox\\VM\\NSProjectRelease\\sampleData\\"+inputFileName;
                    //String fileName = "C:\\Users\\zhexian\\Dropbox\\VM\\NSProjectRelease\\sampleData\\smallFile.txt";
                    //String fileName = "C:\\Users\\valer_000\\Google Drive\\CSE\\Projects\\NSProjectRelease\\sampleData\\smallFile.txt";
                    File file_to_server = new File(fileName);
                    String data = "";
                    String line;
                    BufferedReader bufferedReader = new BufferedReader(new FileReader(fileName));
                    //parse file content into byte array
                    while ((line = bufferedReader.readLine()) != null) {
                        data = data + "\n" + line;
                    }
                    FileInputStream fileInputStream = null;
                    byte[] input_file_as_byte_array = new byte[(int) file_to_server.length()];
                    int file_byte_length= input_file_as_byte_array.length;
                    System.out.println("input file byte array length= "+ input_file_as_byte_array.length);
                    try {
                        //convert file into byte array
                        fileInputStream = new FileInputStream(file_to_server);
                        fileInputStream.read(input_file_as_byte_array);
                        fileInputStream.close();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

                    //generate session secret key using AES algorithm
                    SecretKey key = KeyGenerator.getInstance("AES").generateKey();

                    //create cipher object, initialize the ciphers with the given key, choose encryption mode as AES
                    Cipher cipher_encrypt = Cipher.getInstance("AES");
                    cipher_encrypt.init(Cipher.ENCRYPT_MODE, key); //init as encrypt mode

                    //do encryption, by calling method Cipher.doFinal().
                    byte[] encryptedBytes = cipher_encrypt.doFinal(input_file_as_byte_array);

                    
                    //send the encryptedBytes.length
                    out.println(encryptedBytes.length);
                    out.flush();

                    //send AES encrypted file to client
                    //use bufferedpOUTPUTSTREAM INSTEAD OF PRINTWRITER FOR IMAGE
                    BufferedOutputStream bufferedOutputStream= new BufferedOutputStream(outputStream_to_server);
                    bufferedOutputStream.write(encryptedBytes, 0, encryptedBytes.length);
                    System.out.println("stream size is: "+encryptedBytes.length);
                    bufferedOutputStream.flush();

                    System.out.println("AES encrypted file sent");  
                                
                    //Create RSA("RSA/ECB/PKCS1Padding") cipher object and initialize is as encrypt mode, 
                    //use PUBLIC key.
                    Cipher rsaCipher_encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    rsaCipher_encrypt.init(Cipher.ENCRYPT_MODE, server_publicKey);

                    //convert secrete AES session key to byte[]
                    byte[] secrete_key_byte = key.getEncoded();

                    //encrypt message
                    byte[] secrete_key_byte_encrypted = rsaCipher_encrypt.doFinal(secrete_key_byte);

                    //convert encrypted AES session key to base64 format
                    String secrete_key_byte_encrypted_string = DatatypeConverter.printBase64Binary(secrete_key_byte_encrypted);

                    out.println(secrete_key_byte_encrypted_string);
                    out.flush();
                    file_sent = true;
                } 

                else{
                    //nonce already verified, wait for server to reply acknowledged
                    String server_bytes_to_string= new String(in.readLine());
                    if(server_bytes_to_string.equals("uploaded file")){
                        upload_acknowledged= true;
                        //close connection when uploaded
                        System.out.println("File uploaded successfully");
                        inputStream_from_server.close();
                        outputStream_to_server.close();
                        clientSocket.close();
                    }
                    else {
                        System.out.println("File was not uploaded successfully");
                        System.exit(1);
                    }

                }
            } while(!upload_acknowledged);

        } catch (FileNotFoundException e) {
            System.out.println("File not found");
        }
        catch (Exception e) {
            e.printStackTrace();
        }

    }

}
