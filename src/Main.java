package src;


import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.List;
import java.security.GeneralSecurityException;
import java.sql.SQLException;

public class Main {

    public static void main(String[] args) { // Catch exceptions at a higher level
        try {
            // Ensure the SQLite JDBC driver is loaded
            Class.forName("org.sqlite.JDBC");
            System.out.println("SQLite JDBC driver loaded.");

            // --- Key Management (Example: Generating a new key each time - NOT SECURE FOR PRODUCTION) ---
            SecretKey key = CryptoUtils.generateKey();
            String base64Key = CryptoUtils.keyToBase64(key);
            System.out.println("Generated new encryption key (Base64): " + base64Key);
            // In a real app, you would load this key securely, not generate it here.

            // Ensure the database table exists
            DatabaseManager.createTokensTable();

            // --- Test Insert Operation ---
            System.out.println("\n--- Testing Insert Operation ---");
            TokenEntry newToken = new TokenEntry(
                    "MySecureToken",
                    "MyService",
                    "super-secret-token",
                    Instant.now().plusSeconds(3600), // valid for 1 hour
                    "{\"info\":\"sample metadata\"}",
                    "Bearer",
                    key // Pass the encryption key
            );

            // Insert the token and get the object with the generated ID
            TokenEntry insertedToken = DatabaseManager.insertToken(newToken, key); // Pass key for return object creation

            if (insertedToken != null) {
                System.out.println("Token stored securely in database with ID: " + insertedToken.getId());

                // --- Test Retrieve by ID Operation ---
                System.out.println("\n--- Testing Retrieve by ID Operation ---");
                System.out.println("Retrieving token with ID: " + insertedToken.getId());
                TokenEntry retrievedToken = DatabaseManager.getTokenById(insertedToken.getId()); // Get the object directly

                if (retrievedToken != null) {
                    // Decrypt the token value using the key
                    String plaintextToken = retrievedToken.getDecryptedToken(key);

                    System.out.println("Decrypted token retrieved: " + plaintextToken);
                    System.out.println("Retrieved Token Details: " + retrievedToken); // Use the updated toString()

                    // --- Test Update Operation ---
                    System.out.println("\n--- Testing Update Operation ---");
                    System.out.println("Attempting to update token with ID: " + retrievedToken.getId());
                    // Create a *new* TokenEntry with updated values (immutability)
                    TokenEntry tokenToUpdate = new TokenEntry(
                            retrievedToken.getId(), // Use the existing ID
                            "Updated Token Name",
                            "Updated Service",
                            retrievedToken.getEncryptedTokenWithIV(), // Keep the existing encrypted value (or re-encrypt if changing plain text)
                            Instant.now().plusSeconds(7200), // Update expiration
                            "{\"info\":\"updated metadata\"}",
                            "Updated Type"
                    );
                    boolean updated = DatabaseManager.updateToken(tokenToUpdate);
                    System.out.println("Update successful: " + updated);

                    // Verify the update
                    System.out.println("\nVerifying update by retrieving again...");
                    TokenEntry verifiedToken = DatabaseManager.getTokenById(tokenToUpdate.getId());
                    if (verifiedToken != null) {
                        System.out.println("Verified Updated Token: " + verifiedToken);
                    }

                } else {
                    System.out.println("Token with ID " + insertedToken.getId() + " not found after retrieval.");
                }

                // --- Test Get All Tokens Operation ---
                System.out.println("\n--- Testing Get All Tokens Operation ---");
                List<TokenEntry> allTokens = DatabaseManager.getAllTokens();
                System.out.println("All Tokens:");
                if (allTokens.isEmpty()) {
                    System.out.println("No tokens found.");
                } else {
                    for (TokenEntry token : allTokens) {
                        System.out.println(token); // Prints the masked encrypted value
                        // To print the decrypted value for all, you would decrypt each one here
                        // try {
                        //     System.out.println(" Decrypted: " + token.getDecryptedToken(key));
                        // } catch (GeneralSecurityException e) {
                        //     System.err.println(" Error decrypting token with ID " + token.getId() + ": " + e.getMessage());
                        // }
                    }
                }

                // --- Test Get Expired Tokens Operation ---
                System.out.println("\n--- Testing Get Expired Tokens Operation ---");
                // Insert an expired token for testing
                TokenEntry expiredToken = new TokenEntry(
                        "ExpiredTokenTest", "TestService", "exp-val", Instant.now().minusSeconds(10), null, "Test", key
                );
                DatabaseManager.insertToken(expiredToken, key); // Insert it

                List<TokenEntry> expiredTokens = DatabaseManager.getExpiredTokens();
                System.out.println("Expired Tokens:");
                if (expiredTokens.isEmpty()) {
                    System.out.println("No expired tokens found.");
                } else {
                    for (TokenEntry token : expiredTokens) {
                        System.out.println(token);
                        try {
                            System.out.println(" Decrypted: " + token.getDecryptedToken(key));
                        } catch (GeneralSecurityException e) {
                            System.err.println(" Error decrypting expired token with ID " + token.getId() + ": " + e.getMessage());
                        }
                    }
                }

                // --- Test Delete Operation ---
                System.out.println("\n--- Testing Delete Operation ---");
                // Find an ID to delete (let's delete the 'expiredToken')
                // We need its ID. If insertToken returned the object with ID, we could use that.
                // Alternatively, we can retrieve all tokens and pick one.
                List<TokenEntry> tokensToDelete = DatabaseManager.getAllTokens();
                if (!tokensToDelete.isEmpty()) {
                    int idToDelete = tokensToDelete.get(tokensToDelete.size() - 1).getId(); // Delete the last inserted (expired) token
                    System.out.println("Attempting to delete token with ID: " + idToDelete);
                    boolean deleted = DatabaseManager.deleteToken(idToDelete);
                    System.out.println("Deletion successful: " + deleted);

                    // Verify deletion
                    System.out.println("\nTokens after deletion:");
                    List<TokenEntry> tokensAfterDelete = DatabaseManager.getAllTokens();
                    if (tokensAfterDelete.isEmpty()) {
                        System.out.println("No tokens found.");
                    } else {
                        for (TokenEntry token : tokensAfterDelete) {
                            System.out.println(token);
                        }
                    }
                } else {
                    System.out.println("No tokens to delete.");
                }

            } else {
                System.out.println("Failed to insert token.");
            }

        } catch (ClassNotFoundException e) {
            System.err.println("Error: SQLite JDBC driver not found.");
            e.printStackTrace();
        } catch (SQLException e) {
            System.err.println("Database error: " + e.getMessage());
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            System.err.println("Security error: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("An unexpected error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
