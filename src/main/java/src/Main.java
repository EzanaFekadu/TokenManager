package src.main.java.src;
import java.sql.ResultSet;
import java.time.Instant;
import javax.crypto.SecretKey;

public class Main {
    public static void main(String[] args) throws Exception {
        Class.forName("org.sqlite.JDBC"); // <-- Add this line

        // Generate or load your secure key
        SecretKey key = CryptoUtils.generateKey();

        // 1. Create a new token
        TokenEntry newToken = new TokenEntry(
            "MySecureToken",
            "MyService",
            "super-secret-token",
            Instant.now().plusSeconds(3600),  // valid for 1 hour
            "{\"info\":\"sample metadata\"}",
            "Bearer",
            key
        );

        // 2. Save the token to database
        DatabaseManager.createTokensTable();
        DatabaseManager.insertToken(newToken);
        System.out.println("Token stored securely in database.");

        // 3. Retrieve the token (simulate fetching by ID)
        try (ResultSet rs = DatabaseManager.getTokenById(1)) {
            if (rs.next()) {
                int id = rs.getInt("id");
                String name = rs.getString("name");
                String service = rs.getString("service");
                String encryptedToken = rs.getString("token_value");
                long expirationEpoch = rs.getLong("expiration_date");
                String metadata = rs.getString("metadata");
                String tokenType = rs.getString("token_type");

                TokenEntry storedToken = new TokenEntry(
                    id,
                    name,
                    service,
                    encryptedToken,
                    Instant.ofEpochSecond(expirationEpoch),
                    metadata,
                    tokenType
                );

                String plaintextToken = storedToken.getDecryptedToken(key);
                System.out.println("Decrypted token retrieved: " + plaintextToken);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}