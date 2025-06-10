package src.main.java.src;
import java.time.Instant;

public final class TokenEntry {
    private final int id;
    private final String name;
    private final String service;
    private final String encryptedToken; // Stores encrypted token
    private final Instant expirationDate;
    private final String metadataJson;
    private final String tokenType;

    public TokenEntry(String name, String service, String tokenValue, Instant expirationDate,
                        String metadataJson, String tokenType, javax.crypto.SecretKey key) throws Exception {
        if (name == null || service == null || tokenValue == null || expirationDate == null || tokenType == null) {
            throw new IllegalArgumentException("Arguments cannot be null");
        }
        this.id = 0; // Not assigned yet
        this.name = name;
        this.service = service;
        this.encryptedToken = CryptoUtils.encrypt(tokenValue, key);
        this.expirationDate = expirationDate;
        this.metadataJson = metadataJson;
        this.tokenType = tokenType;
    }

    public TokenEntry(int id, String name, String service, String encryptedToken,
                        Instant expirationDate, String metadataJson, String tokenType) {
        this.id = id;
        this.name = name;
        this.service = service;
        this.encryptedToken = encryptedToken;
        this.expirationDate = expirationDate;
        this.metadataJson = metadataJson;
        this.tokenType = tokenType;
    }

    public int getId() { return id; }
    public String getName() { return name; }
    public String getService() { return service; }
    public String getEncryptedToken() { return encryptedToken; }
    public Instant getExpirationDate() { return expirationDate; }
    public String getMetadataJson() { return metadataJson; }
    public String getTokenType() { return tokenType; }

    public String getDecryptedToken(javax.crypto.SecretKey key) throws Exception {
        return CryptoUtils.decrypt(encryptedToken, key);
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expirationDate);
    }

    @Override
    public String toString() {
        return "TokenEntry{id=" + id +
                ", name='" + name + '\'' +
                ", service='" + service + '\'' +
                ", encryptedToken='[PROTECTED]'" +
                ", expirationDate=" + expirationDate +
                ", metadataJson='" + metadataJson + '\'' +
                ", tokenType='" + tokenType + '\'' +
                '}';
    }
}