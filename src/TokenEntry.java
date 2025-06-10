package src;


import java.time.Instant;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException; // For cryptographic errors

public final class TokenEntry {

    private final int id; // Database ID
    private final String name;
    private final String service;
    private final String encryptedTokenWithIV; // Stores encrypted token with IV (Base64)
    private final Instant expirationDate;
    private final String metadataJson;
    private final String tokenType;

    // Constructor for creating new TokenEntry objects before they are saved to the database
    // Takes plain token value and the key for encryption
    public TokenEntry(String name, String service, String tokenValue, Instant expirationDate,
                        String metadataJson, String tokenType, SecretKey encryptionKey) throws GeneralSecurityException, IllegalArgumentException {

        if (name == null || tokenValue == null || tokenType == null) {
            throw new IllegalArgumentException("Name, tokenValue, and tokenType cannot be null");
        }
        // Service and metadataJson can be null based on our schema

        this.id = 0; // ID is assigned by the database
        this.name = name;
        this.service = service; // Can be null
        this.encryptedTokenWithIV = CryptoUtils.encrypt(tokenValue, encryptionKey); // Encrypt here
        this.expirationDate = expirationDate; // Can be null in database if not set
        this.metadataJson = metadataJson; // Can be null
        this.tokenType = tokenType;
    }

    // Constructor for creating TokenEntry objects from database rows
    // Takes the already encrypted token string from the database
    public TokenEntry(int id, String name, String service, String encryptedTokenWithIV,
                        Instant expirationDate, String metadataJson, String tokenType) throws IllegalArgumentException {

        if (name == null || encryptedTokenWithIV == null || tokenType == null) {
            throw new IllegalArgumentException("Name, encryptedTokenWithIV, and tokenType cannot be null");
        }

        this.id = id;
        this.name = name;
        this.service = service;
        this.encryptedTokenWithIV = encryptedTokenWithIV; // Store the encrypted string
        this.expirationDate = expirationDate;
        this.metadataJson = metadataJson;
        this.tokenType = tokenType;
    }

    // --- Getters ---
    public int getId() { return id; }
    public String getName() { return name; }
    public String getService() { return service; }
    // Getter for the stored encrypted value (includes IV)
    public String getEncryptedTokenWithIV() { return encryptedTokenWithIV; }
    public Instant getExpirationDate() { return expirationDate; }
    public String getMetadataJson() { return metadataJson; }
    public String getTokenType() { return tokenType; }

    /**
     * Decrypts the stored token value.
     * @param decryptionKey The SecretKey to use for decryption.
     * @return The original plain text token value.
     * @throws GeneralSecurityException if decryption fails (e.g., incorrect key, tampered data).
     */
    public String getDecryptedToken(SecretKey decryptionKey) throws GeneralSecurityException {
        if (decryptionKey == null) {
            throw new IllegalArgumentException("Decryption key cannot be null.");
        }
        // Use CryptoUtils to decrypt the stored encrypted string
        return CryptoUtils.decrypt(encryptedTokenWithIV, decryptionKey);
    }

    /**
     * Checks if the token has expired based on the current time.
     * @return true if the expiration date is not null and is before the current time, false otherwise.
     */
    public boolean isExpired() {
        // A token without an expiration date is not considered expired by this logic
        return expirationDate != null && Instant.now().isAfter(expirationDate);
    }

    @Override
    public String toString() {
        return "TokenEntry{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", service='" + service + '\'' +
                ", encryptedTokenWithIV='[PROTECTED]'" + // Always mask the encrypted value
                ", expirationDate=" + expirationDate +
                ", metadataJson='" + metadataJson + '\'' +
                ", tokenType='" + tokenType + '\'' +
                '}';
    }

    // Note: No setters are included as the class is immutable (fields are final).
    // Updates would involve creating a new TokenEntry object.
}