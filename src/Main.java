package src;

import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.SecretKey;

public class Main {

    private static final Logger logger = Logger.getLogger(Main.class.getName());

    public static void main(String[] args) {
        try {
            Class.forName("org.sqlite.JDBC");
            logger.info("SQLite JDBC driver loaded.");

            SecretKey key = CryptoUtils.generateKey();
            String base64Key = CryptoUtils.keyToBase64(key);
            logger.log(Level.INFO, "Generated new encryption key (Base64): {0}", base64Key);

            DatabaseManager.createTokensTable();

            TokenEntry insertedToken = testInsertOperation(key);

            if (insertedToken != null) {
                TokenEntry retrievedToken = testRetrieveByIdOperation(insertedToken, key);
                if (retrievedToken != null) {
                    testUpdateOperation(retrievedToken);
                }
                testGetAllTokensOperation();
                testGetExpiredTokensOperation(key);
                testDeleteOperation();
            } else {
                logger.warning("Failed to insert token.");
            }

        } catch (ClassNotFoundException e) {
            logger.log(Level.SEVERE, "Error: SQLite JDBC driver not found.", e);
        } catch (SQLException e) {
            logger.log(Level.SEVERE, e, () -> "Database error: " + e.getMessage());
        } catch (GeneralSecurityException e) {
            logger.log(Level.SEVERE, e, () -> "Security error: " + e.getMessage());
        } catch (Exception e) {
            logger.log(Level.SEVERE, "An unexpected error occurred.", e);
        }
    }

    private static TokenEntry testInsertOperation(SecretKey key) throws GeneralSecurityException, SQLException {
        logger.info("\n--- Testing Insert Operation ---");
        TokenEntry newToken = new TokenEntry(
                "MySecureToken",
                "MyService",
                "super-secret-token",
                Instant.now().plusSeconds(3600), // valid for 1 hour
                "{\"info\":\"sample metadata\"}",
                "Bearer",
                key // Pass the encryption key
        );
        TokenEntry insertedToken = DatabaseManager.insertToken(newToken, key); // Pass key for return object creation
        if (insertedToken != null) {
            logger.log(Level.INFO, "Token stored securely in database with ID: {0}", insertedToken.getId());
        }
        return insertedToken;
    }

    private static TokenEntry testRetrieveByIdOperation(TokenEntry insertedToken, SecretKey key) throws GeneralSecurityException, SQLException {
        logger.info("\n--- Testing Retrieve by ID Operation ---");
        logger.log(Level.INFO, "Retrieving token with ID: {0}", insertedToken.getId());
        TokenEntry retrievedToken = DatabaseManager.getTokenById(insertedToken.getId()); // Get the object directly

        if (retrievedToken != null) {
            // Decrypt the token value using the key
            String plaintextToken = retrievedToken.getDecryptedToken(key);

            logger.log(Level.INFO, "Decrypted token retrieved: {0}", plaintextToken);
            logger.log(Level.INFO, "Retrieved Token Details: {0}", retrievedToken); // Use the updated toString()
        } else {
            logger.log(Level.WARNING, "Token with ID {0} not found after retrieval.", insertedToken.getId());
        }
        return retrievedToken;
    }

    private static void testUpdateOperation(TokenEntry retrievedToken) throws SQLException, GeneralSecurityException {
        logger.info("\n--- Testing Update Operation ---");
        logger.log(Level.INFO, "Attempting to update token with ID: {0}", retrievedToken.getId());
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
        logger.log(Level.INFO, "Update successful: {0}", updated);

        // Verify the update
        logger.info("\nVerifying update by retrieving again...");
        TokenEntry verifiedToken = DatabaseManager.getTokenById(tokenToUpdate.getId());
        if (verifiedToken != null) {
            logger.log(Level.INFO, "Verified Updated Token: {0}", verifiedToken);
        }
    }

    private static void testGetAllTokensOperation() throws SQLException, GeneralSecurityException {
        logger.info("\n--- Testing Get All Tokens Operation ---");
        List<TokenEntry> allTokens = DatabaseManager.getAllTokens();
        logger.info("All Tokens:");
        if (allTokens.isEmpty()) {
            logger.info("No tokens found.");
        } else {
            for (TokenEntry token : allTokens) {
                if (logger.isLoggable(Level.INFO)) {
                    logger.info(token.toString());
                } // Prints the masked encrypted value
                
            }
        }
    }

    private static void testGetExpiredTokensOperation(SecretKey key) throws GeneralSecurityException, SQLException {
        logger.info("\n--- Testing Get Expired Tokens Operation ---");
        // Insert an expired token for testing
        TokenEntry expiredToken = new TokenEntry(
                "ExpiredTokenTest", "TestService", "exp-val", Instant.now().minusSeconds(10), null, "Test", key
        );
        DatabaseManager.insertToken(expiredToken, key); // Insert it

        List<TokenEntry> expiredTokens = DatabaseManager.getExpiredTokens();
        logger.info("Expired Tokens:");
        if (expiredTokens.isEmpty()) {
            logger.info("No expired tokens found.");
        } else {
            for (TokenEntry token : expiredTokens) {
                if (logger.isLoggable(Level.INFO)) {
                            logger.info(token.toString());
                        }
                    
                
                try {
                    if (logger.isLoggable(Level.INFO)) {
                        logger.log(Level.INFO, " Decrypted: {0}", token.getDecryptedToken(key));
                    }
                } catch (GeneralSecurityException e) {
                    logger.log(Level.SEVERE, 
                        "Error decrypting expired token with ID {0}: {1}", 
                        new Object[]{token.getId(), e.getMessage()}
                    );
                }
            }
        }
    }

    private static void testDeleteOperation() throws SQLException, GeneralSecurityException {
        logger.info("\n--- Testing Delete Operation ---");
        List<TokenEntry> tokensToDelete = DatabaseManager.getAllTokens();
        if (!tokensToDelete.isEmpty()) {
            int idToDelete = tokensToDelete.get(tokensToDelete.size() - 1).getId(); // Delete the last inserted (expired) token
            logger.log(Level.INFO, "Attempting to delete token with ID: {0}", idToDelete);
            boolean deleted = DatabaseManager.deleteToken(idToDelete);
            logger.log(Level.INFO, "Deletion successful: {0}", deleted);

            // Verify deletion
            logger.info("\nTokens after deletion:");
            List<TokenEntry> tokensAfterDelete = DatabaseManager.getAllTokens();
            if (tokensAfterDelete.isEmpty()) {
                logger.info("No tokens found.");
            } else {
                for (TokenEntry token : tokensAfterDelete) {
                    if (logger.isLoggable(Level.INFO)) {
                            logger.info(token.toString());
                        }
                }
            }
        } else {
            logger.info("No tokens to delete.");
        }
    }
}
