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
//TODO(objective): implement a secure file upload application from a client(myself) to an Internet file server(Secstore)


public class FileUploadApplication {

    public static void main(String args[]) {

//TODO: 1. FIXED VERSION OF AP PROTOCOL: - use nonce? authenticate identity of file server(SecStore)

        //FIRST, must obtain a trusted Secstore public key
        //make use of CERTIFICATE(from CSE-CA) to verify server's signed certifcate (use X509CERT class in java)
        //todo:- extract CA's public key from CA's cert
        //todo:-use CA public key to verify server's signed cert
        //todo: ask Secstore to sign a msg using its PRIVATE key. receive msg,
        //todo: use Secstore's (trusted) public key to verify signed msg

        String hostName = "10.12.22.161";
        int portNumber = 43211;

        byte[] decrypted_nonce; //todo: what to do with this?

        //String my_nonce = "kukuru";
        String my_nonce = "k";

        boolean nonce_verified= false;
        boolean upload_acknowledged=false;

        String server_bytes_to_string= null;

        //TODO: val: send plain R to zhexian
        //TODO: zhexian will encrypt R using her privat eky
        //TODO: val: on my side, obtain z's public key from CA
        //todo: decrypt to get plain R and check if match

        //todo: check that server acknowledged file upload, print n close connection
        try {
            //obtain and verify public key
            //1. Create X509 Certificate object

            // InputStream certFileInputStream = new FileInputStream("C:\\Users\\valer_000\\AndroidStudioProjects\\" +
            //         "CSE\\nslabs\\src\\main\\java\\nsproject\\Signed Certificate - 1001191.crt");
            InputStream certFileInputStream = new FileInputStream("C:\\Users\\zhexian\\Dropbox\\VM\\NSProjectRelease\\"+
                "Signed Certificate - 1001214.crt\\Signed Certificate - 1001214.crt");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate CAcert = (X509Certificate) cf.generateCertificate(certFileInputStream);
            //2. Check validity of signed cert, if not valid an exception will be thrown
            try{ 
                CAcert.checkValidity();
                System.out.println("public key certificate checked");
            }
            // CertificateExpiredException - if the certificate has expired.
            catch (CertificateExpiredException e){
                e.printStackTrace();
            }
            // CertificateNotYetValidException - if the certificate is not yet valid.
            catch (CertificateNotYetValidException e){
                e.printStackTrace();
            }
            //!!!!TODO: verify the public key 
            //3.Extract public key from X509 cert object
            PublicKey server_publicKey = CAcert.getPublicKey();
            
            //CREATE TCP CONNECTIONS - CONNECT TO SERVER 
            //(keep it open, use while to keep listening for rpelies)
            Socket clientSocket = new Socket(hostName, portNumber);

            //todo: convert inputstream into bytes
            InputStream inputStream_from_server = clientSocket.getInputStream();
            InputStreamReader isr = new InputStreamReader(inputStream_from_server);
            BufferedReader in = new BufferedReader(isr);
            OutputStream outputStream_to_server = clientSocket.getOutputStream();
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(),true);

            //encrypted_nonce = outputByteStream_to_server.toByteArray();

            //broadcast nonce (an int) to server (send without encryption)
            //printwriter is used

            out.println(my_nonce);
            out.flush();
            System.out.println("plain nonce sent");

            //received encrypted nonce back from server

            String encrypted_nonce_string = in.readLine();
            System.out.println("encrypted nonce received: "+encrypted_nonce_string);

            //convert encrypted nonce to byte[] format
            byte[] encrypted_nonce = DatatypeConverter.parseBase64Binary(encrypted_nonce_string);
            //decrypt the nonce and compare with original nonce
            //Create RSA("RSA/ECB/PKCS1Padding") cipher object and initialize is as 
            //decrypt mode, use PUBLIC key.
            Cipher rsaCipher_decrypt_nonce= Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher_decrypt_nonce.init(Cipher.DECRYPT_MODE, server_publicKey);
            //decrypt to get plain R and check if match
            decrypted_nonce= rsaCipher_decrypt_nonce.doFinal(encrypted_nonce);
            System.out.println("decrypted_nonce: "+decrypted_nonce);
            //convert Bytes into String
            server_bytes_to_string= new String(decrypted_nonce);
            if(server_bytes_to_string.equals(my_nonce)){
                System.out.println("nonce matched");
            }

            //TODO: use a do-while loop (1st, check nonce correct, send file, then acknowledged, close connection)
            // do{  //TODO: implement like a state machine
            //     //each time, keep creating a new byte array to "download" bytes from server
            //     byte[] input_from_server = new byte[16384];
            //     while ((numberRead = inputStream_from_server.read(input_from_server, 0, input_from_server.length)) != -1) {
            //         outputByteStream_to_server.write(input_from_server, 0, numberRead); //transfer bytes from inputstream to Bytearrayoutputstream
            //     }
            //     outputByteStream_to_server.flush();
            //     input_from_server= outputByteStream_to_server.toByteArray(); //SEE UDP EXAMPLE?
            //     //TODO: decrypt session key (NONCE) sent by server

            //     if(!nonce_verified){
            //         //TODO: Create RSA("RSA/ECB/PKCS1Padding") cipher object and initialize is as decrypt mode, use PUBLIC key.
            //         Cipher rsaCipher_decrypt_nonce= Cipher.getInstance("RSA/ECB/PKCS1Padding");
            //         rsaCipher_decrypt_nonce.init(Cipher.DECRYPT_MODE, server_publicKey);
            //         //todo: decrypt to get plain R and check if match
            //         decrypted_nonce= rsaCipher_decrypt_nonce.doFinal(input_from_server);
            //         //convert Bytes into String
            //         server_bytes_to_string= new String(decrypted_nonce);
            //         if(server_bytes_to_string.equals(my_nonce)){
            //             nonce_verified= true;
            //             //todo: send file (move in rest of code)
            //             String fileName = "C:\\Users\\valer_000\\Google Drive\\CSE\\Projects\\NSProjectRelease\\sampleData\\smallFile.txt";
            //             File file_to_server = new File(fileName);
            //             String data = "";
            //             String line;
            //             BufferedReader bufferedReader = new BufferedReader(new FileReader(fileName));
            //             while ((line = bufferedReader.readLine()) != null) {
            //                 data = data + "\n" + line;
            //             }
            //             //Testing
            //             //System.out.println("File content:\n " + data);
            //             //TODO: Calculate message digest, using MD5 hash function
            //             MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            //             //supply with input data (byte stream) using update() method
            //             FileInputStream fileInputStream = null;
            //             byte[] input_file_as_byte_array = new byte[(int) file_to_server.length()];

            //             try {
            //                 //convert file into byte array
            //                 fileInputStream = new FileInputStream(file_to_server);
            //                 fileInputStream.read(input_file_as_byte_array);
            //                 fileInputStream.close();
            //             } catch (Exception e) {
            //                 e.printStackTrace();
            //             }
            //             messageDigest.update(input_file_as_byte_array);
            //             byte[] digest = messageDigest.digest(data.getBytes());  ///the data is the file
            //             //u sign msgdigest with key
            //             //TODO: Create RSA("RSA/ECB/PKCS1Padding") cipher object and initialize is as encrypt mode, use PRIVATE key.
            //             Cipher rsaCipher_encrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            //             rsaCipher_encrypt.init(Cipher.ENCRYPT_MODE, server_publicKey);
            //             //TODO: encrypt digest message (signed using RSA)
            //             byte[] encryptedBytes = rsaCipher_encrypt.doFinal(digest); //DIGEST = OBJECT BYTE
            //             System.out.println("Length of output message digest(signed with RSA) byte[]: " + encryptedBytes.length);

            //             //TODO: SEND TO SECSTORE
            //             outputStream_to_server.write(encryptedBytes);
            //             outputStream_to_server.flush();
            //         }
            //         else{
            //             System.out.println("Incorrect nonce");
            //             System.exit(1);
            //         }
            //     }
            //     else{
            //         //TODO: NEED TO MAKE A TIMEOUT?

            //         //nonce verified already, wait for server to reply acknowledged
            //         server_bytes_to_string= new String(input_from_server);
            //         if(server_bytes_to_string.equals("uploaded file")){
            //             upload_acknowledged= true;
            //         }
            //         else {
            //             System.out.println("File was not uploaded successfully");
            //             System.exit(1);
            //         }

            //     }
            // }while(!upload_acknowledged);

            // //TODO: close connection when uploaded
            // System.out.println("File uploaded successfully");
            // inputStream_from_server.close();
            // outputStream_to_server.close();
            // clientSocket.close();



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
