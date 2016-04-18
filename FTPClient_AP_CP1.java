package nsproject;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
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

import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

//import sun.misc.IOUtils;

/**
 * Created by valerie_tan on 4/12/2016.
 */
//objective: implement a secure file upload application from a client(myself) to an Internet file server(Secstore)


public class FTPClient_AP_CP1 {

    public static void main(String args[]) {

        String hostName = "10.12.22.161";
        int portNumber = 43211;
    
        String my_nonce = "kukuru";

        boolean file_sent = false;
        boolean upload_acknowledged = false;

//1. FIXED VERSION OF AP PROTOCOL: - use nonce to authenticate identity of file server(SecStore)

        //FIRST, must obtain a trusted Secstore public key
        //make use of CERTIFICATE(from CSE-CA) to verify server's signed certifcate (use X509CERT class in java)
        //TODO:- extract CA's public key from CA's cert
        //TODO: - use CA public key to verify server's signed cert
        //ask Secstore to sign a msg using its PRIVATE key. receive msg,
        //use Secstore's (trusted) public key to verify signed msg        
        try {
            //1. Create X509 Certificate object
            InputStream caCertInputStream= new FileInputStream("C:\\Users\\zhexian\\Documents\\GitHub\\Encrypted_FTP_NSproject\\CA.crt"); //TODO: REPLACE WITH ADDRESS
            CertificateFactory cf_ca= CertificateFactory.getInstance("X.509");
            X509Certificate CAcert= (X509Certificate) cf_ca.generateCertificate(caCertInputStream);

            try{
                CAcert.checkValidity();
                System.out.println("CA certificate checked");
            }catch (CertificateExpiredException e){
                e.printStackTrace();
            } catch (CertificateNotYetValidException e){
                e.printStackTrace();
                System.out.println("CA certificate not yet valid");
            }

            //TODO: verify CA using its own public key
            PublicKey CA_Key = CAcert.getPublicKey();
            // try {
            //     CAcert.verify(CA_Key);
            // }catch (Exception e){
            //     e.printStackTrace();
            //     System.out.println("Verification for CA cert gone wrong");
            // }

            //TODO: CREATE OBJECT FOR MY CERT, VALIDIFY AND VERIFY

            // InputStream certFileInputStream = new FileInputStream("C:\\Users\\valer_000\\AndroidStudioProjects\\" +
            //         "CSE\\nslabs\\src\\main\\java\\nsproject\\Signed Certificate - 1001191.crt");
            InputStream certFileInputStream = new FileInputStream("C:\\Users\\zhexian\\Dropbox\\VM\\NSProjectRelease\\"+
                    "Signed Certificate - 1001214.crt\\Signed Certificate - 1001214.crt");
            CertificateFactory cf_myself = CertificateFactory.getInstance("X.509");
            X509Certificate MyCert = (X509Certificate) cf_myself.generateCertificate(certFileInputStream);
            //2. Check validity of signed cert, if not valid an exception will be thrown
            try{
                MyCert.checkValidity();
                System.out.println("public key certificate checked");
            }
            // CertificateExpiredException - if the certificate has expired.
            catch (CertificateExpiredException e){
                e.printStackTrace();
            }
            // CertificateNotYetValidException - if the certificate is not yet valid.
            catch (CertificateNotYetValidException e){
                e.printStackTrace();
                System.out.println("My certificate not yet valid");
            }
            //TODO: verify my cert using its own public key
            //3.Extract public key from X509 cert object
            PublicKey server_publicKey = MyCert.getPublicKey();
            // try {
            //     MyCert.verify(server_publicKey);
            // }catch (Exception e){
            //     e.printStackTrace();
            //     System.out.println("Verification for MY cert gone wrong");
            // }
            //////////////////////////////////////////////////////////////////////////////////////////////////


            //CREATE TCP CONNECTIONS - CONNECT TO SERVER 
            Socket clientSocket = new Socket(hostName, portNumber);

            InputStream inputStream_from_server = clientSocket.getInputStream();
            InputStreamReader isr = new InputStreamReader(inputStream_from_server);
            BufferedReader in = new BufferedReader(isr);
            OutputStream outputStream_to_server = clientSocket.getOutputStream();
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(),true);

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

            //check that server acknowledged file upload, print and close connection
            //use a do-while loop (send file, receive acknowledgment, close connection)
            do{
                if(!file_sent){
                    //send file (move in rest of code)
                    String fileName = "C:\\Users\\zhexian\\Dropbox\\VM\\NSProjectRelease\\sampleData\\smallFile.txt";
                    //String fileName = "C:\\Users\\valer_000\\Google Drive\\CSE\\Projects\\NSProjectRelease\\sampleData\\smallFile.txt";
                    File file_to_server = new File(fileName);
                    String data = "";
                    String line;
                    BufferedReader bufferedReader = new BufferedReader(new FileReader(fileName));
                    while ((line = bufferedReader.readLine()) != null) {
                        data = data + "\n" + line;
                    }
                    //Testing
                    //System.out.println("File content:\n " + data);
                    //TODO: Calculate message digest, using MD5 hash function
                    //MessageDigest messageDigest = MessageDigest.getInstance("MD5");
                    //supply with input data (byte stream) using update() method
                    FileInputStream fileInputStream = null;
                    byte[] input_file_as_byte_array = new byte[(int) file_to_server.length()];

                    try {
                        //convert file into byte array
                        fileInputStream = new FileInputStream(file_to_server);
                        fileInputStream.read(input_file_as_byte_array);
                        fileInputStream.close();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    //messageDigest.update(input_file_as_byte_array);
                    //byte[] digest = messageDigest.digest(data.getBytes());  //the data is the file
                    //sign msgdigest with key

                    //Create RSA("RSA/ECB/PKCS1Padding") cipher object and initialize is as encrypt mode, 
                    //use PUBLIC key.
                    Cipher rsaCipher_encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    rsaCipher_encrypt.init(Cipher.ENCRYPT_MODE, server_publicKey);

                    //divide message into blocks of 117 bytes (so that with 11 bytes padding total is 128 bytes)
                    //--------check with TA should I do this---------
                    //-----or should use message digest? How to convert back to original file----------
                    
                    //encrypt message
                    byte[] encryptedBytes = rsaCipher_encrypt.doFinal(input_file_as_byte_array);
                    System.out.println("Length of output message digest(signed with RSA) byte[]: " + input_file_as_byte_array.length);

                    //SEND TO SECSTORE
                    out.write(new String(encryptedBytes)+"\n");
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

            //TODO: convert file into byte stream

            //TODO:IMPROVE AP PROTOCOL(NONCE?)plus MD5 HASHING AND PADDING - FOLLOW LAB 2)
            //TODO: client side: encrypt data (hash + original file)? using server's PUBLIC KEY


//TODO: 2.  CONFIDENTIALITY PROTOCOL (TWO TYPES)
            //todo: FILE UPLOAD: implement using TCP sockets(ref software construction)
            //todo: client handshake with Server SecStore, then upload

            //TODO: use RSA to implement CP1 - using public key cryptography to ENCRYPT, use Secstore to decrypt
            //todo:client encrypts file data(in units of blocks- for RSA key size of 1024 bits
            //todo:max block length = 117 bytes) Before sending
            //todo: SecStore decrypts data received



            //TODO: use AES(use ECB mode) to implement CP2- which negotiates a shared session key btw client and server
            //still using nonce
            //todo:CPS uses this session key to provide confidentiality of file data
            //todo:session key based on AES(key size of 128 bits, generated using Java JCE)
            //note: a symmetric key crypto sys is much faster than RSA

            //TODO(after coding): Measure data upload time costs of CP1 CP2 for files of diff sizes(provided).
            // Plot results, compare performance

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
