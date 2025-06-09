package net.etf.auth;

import net.etf.Main;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

public class User
{
    private static final String[] HASH_ALGORITHMS = {"MD5", "SHA-256", "SHA-512"};
    private static final String[] ENCRYPTION_ALGORITHMS = { "RC4", "DESede", "AES"};
    private static final String SYMMETRIC_KEY_DIR = "./data/sym_keys";
    private static int counter = 0;

   private String username;
   private String passwordHash;
   private String homeDirectory;
   private File certificateFile;
   private PrivateKey privateKey;
   private PublicKey publicKey;
   private SecretKey symmetricKey;
   private String hashAlgorithm;
   private String encryptionAlgorithm;

   public User(String username, String passwordHash, String homeDirectory, File certificateFile)
   {
       this.username = username;
       this.passwordHash = passwordHash;
       this.homeDirectory = homeDirectory;
       this.certificateFile = certificateFile;
       loadKeysFromCertificate();
       loadOrGenerateSymmetricKey();
   }

    private void loadKeysFromCertificate()
    {
        try{
            String index = getIndex(certificateFile);

            this.privateKey = loadPrivateKeyFromFile("data/keys/private" + index + ".key");
            this.publicKey = loadPublicKeyFromCertificate(certificateFile);
        }catch(Exception e)
        {
            e.printStackTrace();
            System.out.println("Greška pri učitavanju ključeva korisnika.");
        }
    }

    private String getIndex(File certificateFile)
    {
        String filenName = certificateFile.getName();
        return filenName.substring(3, filenName.indexOf(".cer"));
    }

    public static PrivateKey loadPrivateKeyFromFile(String keyFilePath) throws Exception
    {
        String keyContent = new String(Files.readAllBytes(Paths.get(keyFilePath)));
        keyContent = keyContent.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] keyBytes = Base64.getDecoder().decode(keyContent);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePrivate(keySpec);
    }

    private PublicKey loadPublicKeyFromCertificate(File certificateFile) throws Exception
    {
        FileInputStream certFileStream = new FileInputStream(certificateFile);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certFileStream);
        certFileStream.close();

        return  certificate.getPublicKey();
    }

   private void loadOrGenerateSymmetricKey()
   {
       File keyFile = new File(SYMMETRIC_KEY_DIR + File.separator + username + ".key");

       if(keyFile.exists())
       {
           System.out.println("Učitavanje simetričnog ključa za korisnika: " + username);
           this.symmetricKey = decryptSymmetricKey(keyFile);
       }else{
           int index = counter++ % ENCRYPTION_ALGORITHMS.length;
           encryptionAlgorithm = ENCRYPTION_ALGORITHMS[index];

           System.out.println("Generisanje simetričnog ključa za korisnika: " + username);
           this.symmetricKey = generateSymmetricKey(encryptionAlgorithm);
           encryptAndSaveSymmetricKey(keyFile);
       }
       int algorithmIndex = getEncryptionAlgorithmIndex(encryptionAlgorithm);
       hashAlgorithm = HASH_ALGORITHMS[algorithmIndex];
   }

   private int getEncryptionAlgorithmIndex(String algorithm) {
       for (int i = 0; i < ENCRYPTION_ALGORITHMS.length; i++) {
           if (ENCRYPTION_ALGORITHMS[i].equals(algorithm)) {
               return i;
           }
       }
       throw new IllegalArgumentException("Nepoznat algoritam: " + algorithm);
   }

   private void encryptAndSaveSymmetricKey(File keyFile)
   {
        try{
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] encryptedAlgorithm = cipher.doFinal(encryptionAlgorithm.getBytes(StandardCharsets.UTF_8));
            byte[] encryptedKey = cipher.doFinal(symmetricKey.getEncoded());

            String fileContent = Base64.getEncoder().encodeToString(encryptedAlgorithm) + "\n" + Base64.getEncoder().encodeToString(encryptedKey);
            Files.write(keyFile.toPath(), fileContent.getBytes());

            System.out.println("Simetrični ključ sigurno sačuvan.");
        }catch(Exception e)
        {
            e.printStackTrace();
            System.out.println("Greška pri enkripciji simetričnog ključa.");
        }
   }

   private SecretKey decryptSymmetricKey(File keyFile)
   {
       try{
           String[] fileContent = new String(Files.readAllBytes(keyFile.toPath())).split("\n");

           byte[] encryptedAlgorithm = Base64.getDecoder().decode(fileContent[0]);
           byte[] encryptedKey = Base64.getDecoder().decode(fileContent[1]);

           Cipher cipher = Cipher.getInstance("RSA");
           cipher.init(Cipher.DECRYPT_MODE, privateKey);

           String storedAlgorithm = new String(cipher.doFinal(encryptedAlgorithm), StandardCharsets.UTF_8);
           byte[] decryptedKey = cipher.doFinal(encryptedKey);

           this.encryptionAlgorithm = storedAlgorithm;
           return new SecretKeySpec(decryptedKey, encryptionAlgorithm);
       }catch(Exception e)
       {
           throw new RuntimeException("Greška pri dekriptovanju simetričnog ključa: " + e.getMessage());
       }
   }

   private SecretKey generateSymmetricKey(String algorithm)
   {
       try {
           KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
           if ("AES".equals(algorithm)) {
               keyGen.init(256);
           } else if ("DESede".equals(algorithm)) {
               keyGen.init(168);
           } else if ("RC4".equals(algorithm)) {
               keyGen.init(128);
           }
           return keyGen.generateKey();
       } catch (NoSuchAlgorithmException e) {
           throw new RuntimeException("Greška prilikom generisanja simetričnog ključa");
       }
   }

   public void addFileToEFS(String hostFilePath, String targetPath)
   {
       try{
           File originalFile = new File(hostFilePath);
           byte[] fileBytes = Files.readAllBytes(originalFile.toPath());

           String hash = generateFileHash(fileBytes);

           byte[] encryptedData = encryptData(fileBytes);

           String targetFileName = originalFile.getName();

           File targetFile = new File(homeDirectory + File.separator + targetPath + File.separator + targetFileName);
           try(FileOutputStream fos = new FileOutputStream(targetFile))
           {
               fos.write(encryptedData);
           }
           Main.fileHashes.put(targetFile.getAbsolutePath(), hash);
           saveFileHashToFile(targetFile.getAbsolutePath(), hash);
           System.out.println("Datoteka uspješno enkriptovana i sačuvana.");
           //System.out.println(Main.fileHashes);
       }catch(Exception e)
       {
           e.printStackTrace();
           System.out.println("Greška pri dodavanju datoteke na EFS.");
       }
   }

   public void saveFileHashToFile(String filePath, String fileHash)
   {
       try (FileWriter writer = new FileWriter("data/hashes.txt", true))
       {
           writer.append(filePath)
                   .append(",")
                   .append(fileHash)
                   .append("\n");
       } catch (IOException e) {
           e.printStackTrace();
           System.out.println("Greška pri upisu u fajl.");
       }
   }

   public void downloadFileFromEFS(String pathToDownload, String outputFilePath)
   {
       try{
           File fileToDownload = new File(pathToDownload);
           byte[] encryptedData = Files.readAllBytes(fileToDownload.toPath());
           byte[] decryptedData = decryptData(encryptedData);
           //System.out.println(new String(decryptedData));
           String storedHash = Main.fileHashes.get(fileToDownload.getAbsolutePath());
           String currentHash = generateFileHash(decryptedData);

           if(storedHash == null || !storedHash.equals(currentHash))
           {
               System.out.println("Narušen je integritet datoteke koju pokušavate preuzeti. Preuzimanje obustavljeno.");
               return;
           }

           String outputFile = outputFilePath + File.separator + fileToDownload.getName();

           try(FileOutputStream fos = new FileOutputStream(outputFile))
           {
               fos.write(decryptedData);
           }
           System.out.println("Datoteka dekriptovana i preuzeta uspješno");
       }catch(Exception e)
       {
           e.printStackTrace();
           System.out.println("Greška pri preuzimanju datoteke.");
       }
   }

   private String generateFileHash(byte[] fileData) throws NoSuchAlgorithmException
   {
       MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
       byte[] hashBytes = digest.digest(fileData);
       return Base64.getEncoder().encodeToString(hashBytes);
   }

   private byte[] encryptData(byte[] data) throws GeneralSecurityException
   {
       Cipher cipher = Cipher.getInstance(encryptionAlgorithm);
       cipher.init(Cipher.ENCRYPT_MODE, symmetricKey);
       return cipher.doFinal(data);
   }

   private byte[] decryptData(byte[] data) throws GeneralSecurityException
   {
       Cipher cipher = Cipher.getInstance(encryptionAlgorithm);
       cipher.init(Cipher.DECRYPT_MODE, symmetricKey);
       return cipher.doFinal(data);
   }

   public void createDirectoryOnEFS(String dirPath)
   {
       File dir = new File(getHomeDirectory() + File.separator + dirPath);
       if(!dir.exists())
       {
           if(dir.mkdirs())
           {
               System.out.println("Uspješno kreiran direktorijum: " + dir.getName() + " na putanji: " + dir.getPath());
           }else {
               System.out.println("Greška pri kreiranju direktorijuma.");
           }
       }else{
           System.out.println("Direktorijum već postoji.");
       }
   }

   public void deleteDirectoryFromEFS(String dirPath)
   {
       File dir = new File(getHomeDirectory() + File.separator + dirPath);
       if(dir.exists() && dir.isDirectory())
       {
           deleteFiles(dir);
           if(dir.delete()) {
               System.out.println("Uspješno obrisan direktorijum: " + dir.getName());
               removeFileHashes(dirPath);
           }else{
               System.out.println("Greška pri brisanju direktorijuma.");
           }
       }else{
           System.out.println("Diretorijum ne postoji.");
       }
   }

   private void deleteFiles(File dir)
   {
       File[] files = dir.listFiles();
       if(files != null)
       {
           for(File f : files)
           {
               if(f.isDirectory())
               {
                   deleteFiles(f);
                   if(f.delete()) {
                       System.out.println("Obrisano " + f.getName());
                   }
               }else if(f.isFile()) {
                   if(f.delete())  {
                       System.out.println("Obrisano " + f.getName());
                   }else{
                       System.out.println("Greška pri brisanju fajla: " + f.getName());
                   }
               }
           }
       }
   }

   private void removeFileHashes(String dirPath)
   {
       File hashFile = new File("./data/hashes.txt");
       File dir = new File(homeDirectory + File.separator + dirPath);
       String absDirPath = dir.getAbsolutePath();
       List<String> updatedLines = new ArrayList<>();

       try(BufferedReader br = new BufferedReader(new FileReader(hashFile)))
       {
           String line;
           while((line = br.readLine()) != null)
           {
               if(!line.startsWith(absDirPath))
               {
                   updatedLines.add(line);
               }
           }
       }catch(Exception e)
       {
           e.printStackTrace();
           System.out.println("Greška pri čitanju fajla sa otiscima.");
       }

       try(BufferedWriter bw = new BufferedWriter(new FileWriter(hashFile)))
       {
            for(String updatedLine : updatedLines)
            {
                bw.write(updatedLine);
                bw.newLine();
            }
       }catch(Exception e)
       {
           e.printStackTrace();
           System.out.println("Greška pri pisanju u fajl sa otiscima.");
       }
   }

   public void shareFile(String recipientUsername, String filePath)
   {
       try{
           User recipient = Main.users.stream()
                   .filter(user -> user.getUsername().equals(recipientUsername))
                   .findFirst()
                   .orElse(null);

           if(recipient == null)
           {
               System.out.println("Korisnik sa datim username-om ne postoji.");
               return;
           }

           PublicKey recipientPublicKey = recipient.getPublicKey();
           if(recipientPublicKey == null)
           {
               System.out.println("Nije pronađen javni ključ primaoca.");
               return;
           }

           File fileToSend = new File(filePath);
           if(!fileToSend.exists())
           {
               System.out.println("Fajl " + filePath + "ne postoji.");
               return;
           }

           byte[] encryptedData = Files.readAllBytes(fileToSend.toPath());
           byte[] decryptedData = decryptData(encryptedData);

           byte[] digitalSignature = generateDigitaleSignature(decryptedData, this.privateKey);

           KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
           keyGenerator.init(256);
           SecretKey aesKey = keyGenerator.generateKey();

           byte[] encryptedFileData = encryptWithAES(decryptedData, aesKey);

           byte[] encryptedAESKey = encryptWithRecipientPublicKey(aesKey.getEncoded(), recipientPublicKey);
           
           File sharedFile = new File(UserAuthentication.SHARED_DIR, recipientUsername + "_" + fileToSend.getName());

           File signatureFile = new File(UserAuthentication.SIGN_DIR, recipientUsername + "_" + fileToSend.getName() + ".sig");

           try(FileOutputStream fos = new FileOutputStream(sharedFile);
           DataOutputStream dos = new DataOutputStream(fos))
           {
               dos.writeInt(encryptedAESKey.length);
               dos.write(encryptedAESKey);
               dos.write(encryptedFileData);
           }

           try(FileOutputStream fosSig = new FileOutputStream(signatureFile))
           {
               fosSig.write(digitalSignature);
           }
           System.out.println("Fajl uspješno podijeljen sa " + recipientUsername);

       }catch(Exception e)
       {
           e.printStackTrace();
       }
   }

   public void receiveFile(String senderUsername,String fileName)
   {
       try{
           User sender = Main.users.stream()
                   .filter(user -> user.getUsername().equals(senderUsername))
                   .findFirst()
                   .orElse(null);

           if(sender == null)
           {
               System.out.println("Korisnik sa datim username-om ne postoji.");
               return;
           }

           File sharedFile = new File(UserAuthentication.SHARED_DIR + File.separator + fileName);
           if(!sharedFile.exists())
           {
               System.out.println("Fajl ne postoji.");
               return;
           }

           File signatureFile = new File(UserAuthentication.SIGN_DIR + File.separator + fileName + ".sig");
           if(!signatureFile.exists())
           {
               System.out.println("Digitalni potpis nije pronadjen.");
               return;
           }

           try(FileInputStream fis = new FileInputStream(sharedFile);
               DataInputStream dis = new DataInputStream(fis)) {

               int keyLength = dis.readInt();
               if (keyLength <= 0 || keyLength > 512) {
                   throw new IOException("Nevalidna dužina enkriptovanog AES ključa: " + keyLength);
               }
               byte[] encryptedAESKey = new byte[keyLength];
               dis.readFully(encryptedAESKey);

               byte[] encryptedFileData = dis.readAllBytes();
               if (encryptedFileData.length == 0) {
                   throw new IOException("Fajl ne sadrži enkriptovane podatke.");
               }

               byte[] digitalSignature = Files.readAllBytes(signatureFile.toPath());

               byte[] aesKeyBytes = decryptWithRecipientPrivateKey(encryptedAESKey, this.privateKey);
               SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");

               byte[] decryptedFileData = decryptWithAES(encryptedFileData, aesKey);

               boolean isSignatureValid = verifyDigitalSignature(decryptedFileData, digitalSignature, sender.getPublicKey());
               if(!isSignatureValid)
               {
                   System.out.println("Digitalni potpis nije validan. Fajl nije preuzet.");
                   return;
               }

               String targetPath = "";
               String hostFilePath = this.homeDirectory + File.separator + fileName;
               Files.write(Paths.get(hostFilePath), decryptedFileData);

               addFileToEFS(hostFilePath, targetPath);
               System.out.println("Primljeni fajl je enkriptovan i sačuvan na EFS.");
           }
       }catch(Exception e)
       {
           e.printStackTrace();
       }
   }

   public byte[] generateDigitaleSignature(byte[] data, PrivateKey privateKey) throws Exception
   {
       Signature signature = Signature.getInstance("SHA256withRSA");
       signature.initSign(privateKey);
       signature.update(data);
       return signature.sign();
   }

   public boolean verifyDigitalSignature(byte[] data, byte[] digitalSignature, PublicKey publicKey) throws Exception
   {
       Signature signature = Signature.getInstance("SHA256withRSA");
       signature.initVerify(publicKey);
       signature.update(data);
       return signature.verify(digitalSignature);
   }

   public byte[] encryptWithAES(byte[] data, SecretKey key) throws GeneralSecurityException {
       Cipher cipher = Cipher.getInstance("AES");
       cipher.init(Cipher.ENCRYPT_MODE, key);
       return cipher.doFinal(data);
   }

   public byte[] decryptWithAES(byte[] data, SecretKey key) throws GeneralSecurityException {
       Cipher cipher = Cipher.getInstance("AES");
       cipher.init(Cipher.DECRYPT_MODE, key);
       return cipher.doFinal(data);
   }

   public byte[] encryptWithRecipientPublicKey(byte[] data, PublicKey publicKey) throws GeneralSecurityException
   {
       Cipher cipher = Cipher.getInstance("RSA");
       cipher.init(Cipher.ENCRYPT_MODE, publicKey);
       return cipher.doFinal(data);
   }

    public byte[] decryptWithRecipientPrivateKey(byte[] data, PrivateKey privateKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public String getHomeDirectory() {
        return homeDirectory;
    }

    public void setHomeDirectory(String homeDirectory) {
        this.homeDirectory = homeDirectory;
    }

    public File getCertificateFile() {
        return certificateFile;
    }

    public void setCertificateFile(File certificateFile) {
        this.certificateFile = certificateFile;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public String toString() {
        return "User{" +
                "username='" + username + '\'' +
                ", passwordHash='" + passwordHash + '\'' +
                ", homeDirectory='" + homeDirectory + '\'' +
                ", certificateFile=" + certificateFile +
                '}';
    }
}
