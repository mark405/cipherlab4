import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;

public class DESEncryption {
    private static final String ALGORITHM = "DES";
    private final SecretKey secretKey;
    private final SecureRandom secureRandom;
    private IvParameterSpec ivSpec;

    public DESEncryption(SecretKey secretKey) {
        this.secretKey = secretKey;
        this.secureRandom = new SecureRandom();
    }

    public String encrypt(String message, String mode, String padding) {
        try {
            String transformation = ALGORITHM + "/" + mode + "/" + padding;
            Cipher encryptCipher = Cipher.getInstance(transformation);

            // Generate IV for non-ECB modes
            if (!mode.equals("ECB")) {
                ivSpec = new IvParameterSpec(secureRandom.generateSeed(8));
                encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            } else {
                encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey);
            }

            byte[] encryptedData = encryptCipher.doFinal(message.getBytes());
            return Base64.getEncoder().encodeToString(encryptedData);
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting data", e);
        }
    }

    public String decrypt(String encryptedMessage, String mode, String padding) {
        try {
            String transformation = ALGORITHM + "/" + mode + "/" + padding;
            Cipher decryptCipher = Cipher.getInstance(transformation);

            // Use stored IV for non-ECB modes
            if (!mode.equals("ECB")) {
                decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            } else {
                decryptCipher.init(Cipher.DECRYPT_MODE, secretKey);
            }

            byte[] decodedData = Base64.getDecoder().decode(encryptedMessage);
            byte[] decryptedData = decryptCipher.doFinal(decodedData);
            return new String(decryptedData);
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting data", e);
        }
    }
}
