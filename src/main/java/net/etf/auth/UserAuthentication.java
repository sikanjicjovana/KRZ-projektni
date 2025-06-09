package net.etf.auth;

import net.etf.Main;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;

public class UserAuthentication
{
    private static final String USERS_FILE = "data/users.txt";
    private static final String EFS_DIRECTORY = "data/efs/";
    private static final String CERTS_DIRECTORY = "data/certs";
    public static final String SHARED_DIR = "data/shared";
    public static final String SIGN_DIR = "data/signatures";
    private static final String[] ALGORITHMS = {"SHA-256", "SHA-512", "MD5"};

    public static boolean register(String username, String password)
    {
        if(userExists(username))
        {
            System.out.println("Username je zauzet!");
            return false;
        }

        String hashedPassword = hashPassword(password);

        File certificateFile = getUnusedCertificate();
        if(certificateFile == null)
        {
            System.out.println("Nema slobodnih sertifikata.");
            return false;
        }

        User newUser = new User(username, hashedPassword, EFS_DIRECTORY + username, certificateFile);
        Main.users.add(newUser);
        saveUserToFile(newUser);

        Path userDir = Paths.get(EFS_DIRECTORY, username);
        try
        {
            Files.createDirectories(userDir);
            System.out.println("Uspješna registracija! Kreiran home direktorijum: " + userDir);
        }catch (IOException e)
        {
            System.out.println("Greška pri kreiranju direktorijuma.");
            return false;
        }
        return true;
    }

    public static boolean login(String username, String password)
    {
        for (User user : Main.users) {
            if (user.getUsername().equals(username) && verifyPassword(password, user.getPasswordHash()))
            {
                if(user.getCertificateFile() == null || !user.getCertificateFile().exists())
                {
                    System.out.println("Korisnik nema dodijeljen sertifikat.");
                    return false;
                }

                String certPath = user.getCertificateFile().getAbsolutePath();

                if(!CertificateVerification.verifyCertificate(Main.ca,certPath))
                {
                    System.out.println("Sertifikat korisnika nije validan!");
                    return false;
                }

                String certCN = null;
                try(FileInputStream fis = new FileInputStream(certPath))
                {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
                    certCN = CertificateVerification.getCommonName(cert);
                }catch(Exception e)
                {
                    e.printStackTrace();
                }

                if(certCN == null || !username.equals(certCN))
                {
                    //System.out.println(certCN);
                    System.out.println("Međutim, common name u sertifikatu ne odgovara username-u.");
                    return false;
                }

                System.out.println("Uspješna prijava!");
                listUserHomeDirectory(username);
                userSession(username);
                return true;
            }
        }
        System.out.println("Pogrešni pristupni podaci.");
        return false;
    }

    public static void userSession(String username)
    {
        User user = Main.users.stream()
                .filter(u -> u.getUsername().equals(username))
                .findFirst().orElse(null);

        Scanner scanner = new Scanner(System.in);
        if(user != null)
        {
            while (true)
            {
                System.out.println();
                System.out.println("Odaberite opciju:");
                System.out.println("-----------------------------------------------");
                System.out.println("| 1 - Dodaj fajl                               |");
                System.out.println("| 2 - Preuzmi fajl                             |");
                System.out.println("| 3 - Dodaj direktorijum                       |");
                System.out.println("| 4 - Obriši direktorijum                      |");
                System.out.println("| 5 - Prikaži dijeljeni direktorijum           |");
                System.out.println("| 6 - Dodaj fajl u dijeljeni direktorijum      |");
                System.out.println("| 7 - Preuzmi fajl iz dijeljenog direktorijuma |");
                System.out.println("| 8 - Odjava                                   |");
                System.out.println("-----------------------------------------------");

                int choice;

                try {
                    choice = Integer.parseInt(scanner.nextLine().trim());
                } catch (NumberFormatException e) {
                    System.out.println("Neispravan unos. Očekivani brojevi od 1 do 8.");
                    continue;
                }

                switch (choice) {
                    case 1:
                        System.out.println("Unesite putanju do datoteke na host FS-u:");
                        String hostPath = scanner.nextLine();
                        System.out.println("Unesite putanju do direktorijuma na EFS-u gdje želite da smjestite datoteku:");
                        String efsPath = scanner.nextLine();
                        user.addFileToEFS(hostPath,efsPath);
                        break;
                    case 2:
                        System.out.println("Unesite putanju do datoteke na EFS-u koju želite da preuzmete:");
                        String efsDownloadPath = scanner.nextLine();
                        System.out.println("Unesite putanju na host FS-u gdje želite da smjestite datoteku:");
                        String hostDownloadPath = scanner.nextLine();
                        user.downloadFileFromEFS(efsDownloadPath, hostDownloadPath);
                        break;
                    case 3:
                        System.out.println("Unesite putanju do novog direktorijuma na EFS-u:");
                        String dirPath = scanner.nextLine();
                        user.createDirectoryOnEFS(dirPath);
                        break;
                    case 4:
                        System.out.println("Unesite putanju do direktorijuma koji želite da obrišete sa EFS-a:");
                        String dirToDelete = scanner.nextLine();
                        user.deleteDirectoryFromEFS(dirToDelete);
                        break;
                    case 5:
                        listSharedDirectory();
                        break;
                    case 6:
                        System.out.println("Unesite username korisnika kome je fajl namjenjen:");
                        String recipient = scanner.nextLine();
                        System.out.println("Unesite ime fajla(mora biti sa Vašeg EFS-a) koji želite da podijelite:");
                        String fileToShare = scanner.nextLine();
                        String fullFilePath = user.getHomeDirectory() + File.separator + fileToShare;
                        user.shareFile(recipient, fullFilePath);
                        break;
                    case 7:
                        System.out.println("Unesite username korisnika čiji fajl preuzimate:");
                        String senderUsername = scanner.nextLine();
                        System.out.println("Unesite fajl iz dijeljenog direktorijuma koji hoćete da preuzmete:");
                        String fileToReceive = scanner.nextLine();
                        user.receiveFile(senderUsername, fileToReceive);
                        break;
                    case 8:
                        System.out.println("Uspješna odjava!");
                        return;
                    default:
                        System.out.println("Nevalidna opcija.");
                }
            }
        }else{
            System.out.println("Ne postoji korisnik sa datim username-om.");
        }
    }



    public static boolean verifyPassword(String inputPassword, String storedHash)
    {
        try{
            String[] parts = storedHash.split("\\$");
            if(parts.length != 3)
            {
                throw new IllegalArgumentException("Neispravan forman heširane lozinke.");
            }
            String algorithm = parts[0];
            byte[] salt = Base64.getDecoder().decode(parts[1]);
            String storedHashBase64 = parts[2];

            MessageDigest md = MessageDigest.getInstance(algorithm);
            md.update(salt);
            byte[] inputHash = md.digest(inputPassword.getBytes());

            return Base64.getEncoder().withoutPadding().encodeToString(inputHash).equals(storedHashBase64);
        }catch (NoSuchAlgorithmException e)
        {
            throw new RuntimeException("Greška pri validaciji lozinke!");
        }
    }

    private static boolean userExists(String username)
    {
        for(User user : Main.users)
        {
            if(user.getUsername().equals(username))
            {
                return true;
            }
        }
        return false;
    }

    private static void saveUserToFile(User user)
    {
        try(BufferedWriter bw = new BufferedWriter(new FileWriter(USERS_FILE, true)))
        {
            bw.write(user.getUsername() + "," + user.getPasswordHash() + "," + user.getCertificateFile().getAbsolutePath() + "\n");
        }catch(IOException e)
        {
            System.out.println("Greška pri upisu u fajl.");
        }
    }

    public static void loadUsers()
    {
        try(BufferedReader br = new BufferedReader(new FileReader(USERS_FILE)))
        {
            String line;
            while((line = br.readLine()) != null)
            {
                String[] parts = line.split(",");
                if(parts.length == 3)
                {
                    Main.users.add(new User(parts[0],parts[1],EFS_DIRECTORY + parts[0],new File(parts[2])));
                }
            }
        }catch(IOException e)
        {
            System.out.println("Greška pri čitanju fajla sa korisničkim podacima.");
        }
    }

    private static File getUnusedCertificate() {
        File certDir = new File(CERTS_DIRECTORY);
        File[] certFiles = certDir.listFiles((dir, name) -> name.endsWith(".cer"));

        if (certFiles == null || certFiles.length == 0) {
            return null;
        }

        Set<String> usedCerts = new HashSet<>();
        for(User user : Main.users)
        {
            if(user.getCertificateFile() != null)
            {
                usedCerts.add(user.getCertificateFile().getAbsolutePath());
            }
        }
        for (File cert : certFiles)
        {
           if(!usedCerts.contains(cert.getAbsoluteFile().getAbsolutePath()))
           {
               return cert.getAbsoluteFile();
           }
        }
        return null;
    }

    private static String hashPassword(String password)
    {
        try{
            String algorithm = ALGORITHMS[new SecureRandom().nextInt(ALGORITHMS.length)];
            MessageDigest digest = MessageDigest.getInstance(algorithm);

            byte[] salt = generateSalt(algorithm);
            digest.update(salt);

            byte[] hashedBytes = digest.digest(password.getBytes());

            String saltBase64 = Base64.getEncoder().withoutPadding().encodeToString(salt);
            String hashBase64 = Base64.getEncoder().withoutPadding().encodeToString(hashedBytes);

            return algorithm + "$" + saltBase64 + "$" + hashBase64;
        }catch(NoSuchAlgorithmException e)
        {
            throw new RuntimeException("Greška pri heširanju lozinke.");
        }
    }

    private static byte[] generateSalt(String algorithm)
    {
        int saltLength;
        switch(algorithm)
        {
            case "MD5":
                saltLength = 8;
                break;
            case "SHA-256":
                saltLength = 16;
                break;
            case "SHA-512":
                saltLength = 32;
                break;
            default:
                throw new RuntimeException("Algoritam " + algorithm + " nije podržan.");
        }
        byte[] salt = new byte[saltLength];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private static void listUserHomeDirectory(String username)
    {
        Path userDir = Paths.get(EFS_DIRECTORY, username);
        System.out.println();
        System.out.println("Sadržaj home direktorijuma za korisnika: " + username);
        System.out.println("-----------------------------------------------");
        listFiles(userDir, 0);
    }

    private static void listSharedDirectory()
    {
        Path sharedDir = Paths.get(SHARED_DIR);
        System.out.println();
        System.out.println("Sadržaj dijeljenog dijektorijuma:");
        System.out.println("---------------------------------");
        listFiles(sharedDir,0);
    }

    private static void listFiles(Path userDir, int depth)
    {
        File[] files = userDir.toFile().listFiles();
        if(files != null && files.length > 0)
        {
            for(File f : files)
            {
                String prefix = " ".repeat(depth * 2);
                if(f.isDirectory())
                {
                    System.out.println(prefix + "Direktorijum: " + f.getName());
                    listFiles(f.toPath(), depth + 1);
                }else if(f.isFile()) {
                    System.out.println(prefix + "-> " + f.getName());
                }
            }
        }else {
            String prefix = " ".repeat(depth * 2);
            System.out.println(prefix + "[Prazan direktorijum] " + userDir.getFileName());
        }
    }

}
