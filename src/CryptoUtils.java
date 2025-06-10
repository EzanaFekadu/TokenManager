package src;


import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec; // Needed for GCM
import javax.crypto.spec.SecretKeySpec;

import java.util.Base64;
import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException; // More specific exception
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class CryptoUtils {

    // Private constructor to prevent instantiation
    private CryptoUtils() {
        throw new UnsupportedOperationException("Utility class");
    }

    private static final String ALGORITHM = "AES";
    // Using AES in GCM mode with NoPadding. GCM is an authenticated encryption mode.
    private static final String FULL_ALGORITHM = "AES/GCM/NoPadding";
    private static final int AES_KEY_SIZE = 256; // or 128
    private static final int GCM_IV_LENGTH = 12; // Standard recommended IV length for GCM
    private static final int GCM_TAG_LENGTH = 16; // Standard GCM authentication tag length (in bytes)

    /**
     * Generates a new AES SecretKey.
     * @return The generated SecretKey.
     * @throws GeneralSecurityException if a cryptographic error occurs.
     */
    public static SecretKey generateKey() throws GeneralSecurityException {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(AES_KEY_SIZE);
        return keyGen.generateKey();
    }

    /**
     * Converts a SecretKey to a Base64 encoded string.
     * (Note: Storing keys as strings is generally not the most secure method.
     * Consider more robust key management solutions in production.)
     * @param key The SecretKey to encode.
     * @return The Base64 encoded key string.
     */
    public static String keyToBase64(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    /**
     * Converts a Base64 encoded key string back to a SecretKey.
     * @param base64Key The Base64 encoded key string.
     * @return The SecretKey object.
     * @throws IllegalArgumentException if the key string is invalid Base64 or key size is incorrect.
     */
    public static SecretKey base64ToKey(String base64Key) {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        if (keyBytes.length * 8 != AES_KEY_SIZE) {
            throw new IllegalArgumentException("Invalid AES key size.");
        }
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }


    /**
     * Encrypts a plain text string using AES/GCM and includes the IV in the output.
     * @param plainText The string to encrypt.
     * @param key The SecretKey to use for encryption.
     * @return A Base64 encoded string containing the IV and the ciphertext.
     * @throws GeneralSecurityException if a cryptographic error occurs.
     */
    public static String encrypt(String plainText, SecretKey key) throws GeneralSecurityException {
        try {
            Cipher cipher = Cipher.getInstance(FULL_ALGORITHM);

            // Generate a unique IV for each encryption
            byte[] ivBytes = new byte[GCM_IV_LENGTH];
            SecureRandom random = new SecureRandom();
            random.nextBytes(ivBytes);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, ivBytes); // GCM tag length in bits

            cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            // Prepend the IV to the encrypted data before Base64 encoding
            byte[] encryptedBytesWithIV = new byte[ivBytes.length + encryptedBytes.length];
            System.arraycopy(ivBytes, 0, encryptedBytesWithIV, 0, ivBytes.length);
            System.arraycopy(encryptedBytes, 0, encryptedBytesWithIV, ivBytes.length, encryptedBytes.length);

            return Base64.getEncoder().encodeToString(encryptedBytesWithIV);

        } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
            // Wrap specific exceptions in a more general security exception
            throw new GeneralSecurityException("Encryption failed", e);
        }
    }

    /**
     * Decrypts a Base64 encoded string (containing IV and ciphertext) using AES/GCM.
     * @param cipherTextWithIV The Base64 encoded string to decrypt.
     * @param key The SecretKey to use for decryption.
     * @return The original plain text string.
     * @throws GeneralSecurityException if a cryptographic error occurs (e.g., decryption failed,
     *                                   data tampered, incorrect key).
     */
    public static String decrypt(String cipherTextWithIV, SecretKey key) throws GeneralSecurityException {
        try {
            Cipher cipher = Cipher.getInstance(FULL_ALGORITHM);

            byte[] decodedBytesWithIV = Base64.getDecoder().decode(cipherTextWithIV);

            // Extract the IV from the beginning of the decoded bytes
            if (decodedBytesWithIV.length < GCM_IV_LENGTH) {
                throw new GeneralSecurityException("Ciphertext is too short to contain IV.");
            }
            byte[] ivBytes = new byte[GCM_IV_LENGTH];
            System.arraycopy(decodedBytesWithIV, 0, ivBytes, 0, GCM_IV_LENGTH);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, ivBytes);

            // Extract the actual encrypted data
            int encryptedDataLength = decodedBytesWithIV.length - GCM_IV_LENGTH;
            byte[] encryptedBytes = new byte[encryptedDataLength];
            System.arraycopy(decodedBytesWithIV, GCM_IV_LENGTH, encryptedBytes, 0, encryptedDataLength);

            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

            byte[] decryptedBytes = cipher.doFinal(encryptedBytes); // This will check the GCM tag

            return new String(decryptedBytes, StandardCharsets.UTF_8);

        } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e) {
             // Wrap specific exceptions in a more general security exception.
             // This can include BadPaddingException or AEADBadTagException
             // if the data was tampered with or the key is incorrect.
            throw new GeneralSecurityException("Decryption failed, data may be tampered or key incorrect", e);
        }
    }
}