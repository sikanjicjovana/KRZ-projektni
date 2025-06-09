package net.etf;

import net.etf.auth.User;
import net.etf.auth.UserAuthentication;

import java.io.*;
import java.util.*;
import java.security.*;

public class Main {

    public static List<User> users = new ArrayList<>();
    public static Map<String,String> fileHashes = new HashMap<>();
    public static String ca = "./data/ca/rootca.pem";

    public static void main(String[] args)
    {
        Scanner scanner = new Scanner(System.in);
        System.out.println();
        System.out.println("Dobrodošli!\n");

        UserAuthentication.loadUsers();
        loadFileHashes();
        //users.stream().forEach(System.out::println);

        while(true) {
            System.out.println();
            System.out.println("Odaberite jednu od ponuđenih opcija:");
            System.out.println("---------------------");
            System.out.println("| 1 - Registaracija |\n| 2 - Prijava       |\n| 3 - Izlaz         |");
            System.out.println("---------------------");

            int choice = -1;

            try{
                choice = Integer.parseInt(scanner.nextLine().trim());
            }catch(NumberFormatException e)
            {
                System.out.println("Greška pri unosu! Očekivane vrijednosti su 1, 2 ili 3.\n");
                continue;
            }

            switch (choice) {
                case 1:
                    System.out.println("Unesite korisničko ime: ");
                    String newUsername = scanner.nextLine();
                    System.out.println("Unesite lozinku: ");
                    String newPassword = scanner.nextLine();
                    UserAuthentication.register(newUsername, newPassword);
                    break;

                case 2:
                    System.out.println("Unesite korisničko ime: ");
                    String username = scanner.nextLine();
                    System.out.println("Unesite lozinku: ");
                    String password = scanner.nextLine();
                    UserAuthentication.login(username, password);
                    break;

                case 3:
                    System.out.println("Kraj rada!");
                    System.exit(0);
                    break;

                default:
                    System.out.println("Neispravan unos!");
            }
        }
    }

    public static void loadFileHashes() {
        fileHashes.clear();
        try (BufferedReader reader = new BufferedReader(new FileReader("data/hashes.txt")))
        {
            String line;
            while ((line = reader.readLine()) != null)
            {
                String[] parts = line.split(",");
                if (parts.length == 2)
                {
                    fileHashes.put(parts[0], parts[1]);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println("Greška pri čitanju fajla sa heš vrijednostima fajlova.");
        }
    }
}

