import javax.crypto.SecretKey;

public class Main {
    public static void main(String[] args) {
        // Generate the DES key
        SecretKey secretKey = DESKeyGenerator.generateKey();

        // Message to be encrypted and decrypted
        String message = "Hello, DES Encryption!";
        String padding = "PKCS5Padding";

        // Modes to test
        String[] modes = {"ECB", "CBC", "CFB", "OFB"};
        DESEncryption desEncryption = new DESEncryption(secretKey);

        // Loop through each mode, encrypt and decrypt
        for (String mode : modes) {
            System.out.println("Mode: " + mode);

            // Encrypt the message
            String encrypted = desEncryption.encrypt(message, mode, padding);
            System.out.println("Encrypted: " + encrypted);

            // Decrypt the message
            String decrypted = desEncryption.decrypt(encrypted, mode, padding);
            System.out.println("Decrypted: " + decrypted);
            System.out.println();
        }
    }
}
