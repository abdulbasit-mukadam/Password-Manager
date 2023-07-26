import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.sql.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class PasswordManager {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/passwords";
    private static final String DB_USER = "abdulbasit";
    private static final String DB_PASSWORD = "test123";
    private static final String SECRET_KEY = "sI2#02Lm2"; // Change this to a strong secret key

    private static Map<String, String> passwordMap = new HashMap<>();
    private static Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        loadPasswordsFromDatabase();

        System.out.println("Password Manager");
        boolean exit = false;

        while (!exit) {
            System.out.println("1. Add Password");
            System.out.println("2. Retrieve Password");
            System.out.println("3. Exit");
            System.out.print("Enter your choice: ");

            int choice = scanner.nextInt();
            scanner.nextLine(); // Clear the newline character from the buffer

            switch (choice) {
                case 1:
                    addPassword();
                    break;
                case 2:
                    retrievePassword();
                    break;
                case 3:
                    System.out.println("Exiting Password Manager...");
                    exit = true;
                    break;
                default:
                    System.out.println("Invalid choice. Try again.");
            }
        }
    }

    private static void loadPasswordsFromDatabase() {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String sql = "SELECT account, password FROM passwords";
            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                ResultSet rs = stmt.executeQuery();
                while (rs.next()) {
                    String account = rs.getString("account");
                    String encryptedPassword = rs.getString("password");
                    passwordMap.put(account, encryptedPassword);
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
            System.out.println("Error loading passwords from the database.");
        }
    }

    private static void addPassword() {
        System.out.print("Enter the account name: ");
        String account = scanner.nextLine();

        System.out.print("Enter the password: ");
        String password = scanner.nextLine();

        try {
            String encryptedPassword = encrypt(password);
            savePasswordToDatabase(account, encryptedPassword);
            passwordMap.put(account, encryptedPassword);
            System.out.println("Password added successfully!");
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error encrypting the password. Please try again.");
        }
    }

    private static void retrievePassword() {
        System.out.print("Enter the account name: ");
        String account = scanner.nextLine();

        String encryptedPassword = passwordMap.get(account);
        if (encryptedPassword != null) {
            try {
                String password = decrypt(encryptedPassword);
                System.out.println("Password for " + account + ": " + password);
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Error decrypting the password. Please try again.");
            }
        } else {
            System.out.println("Account not found.");
        }
    }

    private static String encrypt(String input) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec secretKeySpec = generateSecretKey();
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] encryptedBytes = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decrypt(String input) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec secretKeySpec = generateSecretKey();
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(input));
        return new String(decryptedBytes);
    }

    private static SecretKeySpec generateSecretKey() throws Exception {
        byte[] key = SECRET_KEY.getBytes("UTF-8");
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        key = sha.digest(key);
        key = java.util.Arrays.copyOf(key, 16); // Use only the first 128 bit
        return new SecretKeySpec(key, "AES");
    }

    private static void savePasswordToDatabase(String account, String encryptedPassword) {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String sql = "INSERT INTO passwords (account, password) VALUES (?, ?)";
            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setString(1, account);
                stmt.setString(2, encryptedPassword);
                stmt.executeUpdate();
            }
        } catch (SQLException e) {
            e.printStackTrace();
            System.out.println("Error saving password to the database.");
        }
    }
}
