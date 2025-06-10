package src;


import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.security.GeneralSecurityException; // For decryption errors

public class DatabaseManager {

    private static final String DATABASE_URL = "jdbc:sqlite:token_management.db";

    /**
     * Establishes a connection to the SQLite database.
     * Handles loading the driver (though often automatic) and connecting.
     * @return A Connection object.
     * @throws SQLException if a database access error occurs.
     */
    public static Connection connect() throws SQLException {
         // Although often automatic, explicitly load the driver for robustness
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException e) {
             // Wrap in SQLException as it's related to database connectivity
            throw new SQLException("SQLite JDBC driver not found.", e);
        }
        return DriverManager.getConnection(DATABASE_URL);
    }

    /**
     * Creates the 'tokens' table if it does not exist.
     * @throws SQLException if a database access error occurs.
     */
    public static void createTokensTable() throws SQLException {
        String sql = "CREATE TABLE IF NOT EXISTS tokens (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                    "name TEXT NOT NULL," +
                    "service TEXT," +
                     "token_value TEXT NOT NULL," + // Stores the encrypted token with IV (Base64)
                     "expiration_date INTEGER," + // Storing as Unix timestamp (seconds)
                     "metadata TEXT," +           // Storing metadata as JSON string
                     "token_type TEXT NOT NULL" + // Making token_type NOT NULL
                    ");";

        // Use try-with-resources to ensure Statement and Connection are closed
        try (Connection conn = connect();
            Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            System.out.println("Table 'tokens' checked/created successfully."); // Using System.out for now
        } catch (SQLException e) {
             System.err.println("Error creating table: " + e.getMessage()); // Using System.err for errors for now
             throw e; // Re-throw the exception to the caller
        }
    }

    /**
     * Inserts a new TokenEntry into the database.
     * Because TokenEntry is immutable and ID is auto-generated, this method
     * inserts the data and returns a new TokenEntry object with the generated ID.
     * @param token The TokenEntry object to insert (ID is ignored).
     * @return A new TokenEntry object with the generated ID, or null if insertion failed.
     * @throws SQLException if a database access error occurs.
     * @throws GeneralSecurityException if a cryptographic error occurs (e.g., during decryption for creating the returned object).
     */
    public static TokenEntry insertToken(TokenEntry token, javax.crypto.SecretKey decryptionKeyForReturn) throws SQLException, GeneralSecurityException {
        String sql = "INSERT INTO tokens(name, service, token_value, expiration_date, metadata, token_type) VALUES(?,?,?,?,?,?)";
        TokenEntry insertedToken = null;

        // Use try-with-resources for Connection and PreparedStatement
        try (Connection conn = connect();
             // Request generated keys when preparing the statement
            PreparedStatement pstmt = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {

            pstmt.setString(1, token.getName());
            // Set nullable fields cautiously
            if (token.getService() != null) {
                pstmt.setString(2, token.getService());
            } else {
                pstmt.setNull(2, java.sql.Types.VARCHAR);
            }

            pstmt.setString(3, token.getEncryptedTokenWithIV()); // Store the encrypted value

            if (token.getExpirationDate() != null) {
                pstmt.setLong(4, token.getExpirationDate().getEpochSecond());
            } else {
                pstmt.setNull(4, java.sql.Types.INTEGER);
            }

            if (token.getMetadataJson() != null) {
                pstmt.setString(5, token.getMetadataJson());
            } else {
                pstmt.setNull(5, java.sql.Types.VARCHAR);
            }

            pstmt.setString(6, token.getTokenType()); // token_type is NOT NULL

            int rowsAffected = pstmt.executeUpdate();

            if (rowsAffected > 0) {
                System.out.println("A new token was inserted successfully.");
                 // Retrieve the generated ID
                try (ResultSet generatedKeys = pstmt.getGeneratedKeys()) {
                    if (generatedKeys.next()) {
                        int generatedId = generatedKeys.getInt(1);

                         // Construct a new TokenEntry object with the generated ID
                         // We need the decryption key here to potentially decrypt
                         // if we were to reconstruct the object fully, but for
                         // an immutable object loaded from DB, we can use the
                         // constructor that takes the encrypted value.
                        insertedToken = new TokenEntry(
                            generatedId,
                            token.getName(),
                             token.getService(), // Pass original values (which might be null)
                             token.getEncryptedTokenWithIV(), // Pass the encrypted value
                            token.getExpirationDate(),
                            token.getMetadataJson(),
                            token.getTokenType()
                        );
                    }
                }
            } else {
                System.err.println("Insert operation did not affect any rows.");
            }

        } catch (SQLException e) {
            System.err.println("Error inserting token: " + e.getMessage());
            throw e; // Re-throw the exception
        } catch (IllegalArgumentException e) {
            System.err.println("Invalid data provided for insertion: " + e.getMessage());
             // Could throw a custom exception here as well
             throw e; // Re-throw the exception
        }
        return insertedToken; // Returns the new object with ID or null
    }


    /**
     * Retrieves a single TokenEntry by its ID.
     * Handles database resource closing internally.
     * @param id The ID of the token to retrieve.
     * @return The TokenEntry object with encrypted token data, or null if not found.
     * @throws SQLException if a database access error occurs.
     * @throws GeneralSecurityException if a cryptographic error occurs during object creation (unlikely here).
     */
    public static TokenEntry getTokenById(int id) throws SQLException, GeneralSecurityException {
        String sql = "SELECT id, name, service, token_value, expiration_date, metadata, token_type FROM tokens WHERE id = ?";
        TokenEntry token = null;

        // Use try-with-resources for Connection and PreparedStatement
        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, id);

            // Use try-with-resources for ResultSet
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    int tokenId = rs.getInt("id");
                    String name = rs.getString("name");
                    String service = rs.getString("service"); // Can be null
                    String encryptedTokenWithIV = rs.getString("token_value"); // This is the encrypted token

                    Instant expirationDate = null;
                    long expirationTimestamp = rs.getLong("expiration_date");
                    if (!rs.wasNull()) { // Check if the retrieved long was NULL
                        expirationDate = Instant.ofEpochSecond(expirationTimestamp);
                    }

                    String metadataJson = rs.getString("metadata"); // Can be null
                    String tokenType = rs.getString("token_type");

                    // Create the TokenEntry object with the retrieved encrypted token value
                    token = new TokenEntry(tokenId, name, service, encryptedTokenWithIV, expirationDate, metadataJson, tokenType);
                }
            } // ResultSet is closed automatically

        } catch (SQLException e) {
            System.err.println("Error retrieving token by ID: " + e.getMessage());
            throw e; // Re-throw the exception
        } catch (IllegalArgumentException e) {
            System.err.println("Error creating TokenEntry from database data: " + e.getMessage());
            // Re-throw as a security exception or a more specific data integrity exception
            throw new GeneralSecurityException("Data integrity issue when creating TokenEntry.", e);
        }
        return token;
    }

    /**
     * Retrieves all TokenEntry objects from the database.
     * Handles database resource closing internally.
     * @return A List of TokenEntry objects with encrypted token data, or an empty list.
     * @throws SQLException if a database access error occurs.
     * @throws GeneralSecurityException if a cryptographic error occurs during object creation (unlikely here).
     */
    public static List<TokenEntry> getAllTokens() throws SQLException, GeneralSecurityException {
        String sql = "SELECT id, name, service, token_value, expiration_date, metadata, token_type FROM tokens";
        List<TokenEntry> tokenList = new ArrayList<>();

        // Use try-with-resources for Connection, Statement, and ResultSet
        try (Connection conn = connect();
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                int tokenId = rs.getInt("id");
                String name = rs.getString("name");
                String service = rs.getString("service");
                String encryptedTokenWithIV = rs.getString("token_value");

                Instant expirationDate = null;
                long expirationTimestamp = rs.getLong("expiration_date");
                if (!rs.wasNull()) {
                    expirationDate = Instant.ofEpochSecond(expirationTimestamp);
                }

                String metadataJson = rs.getString("metadata");
                String tokenType = rs.getString("token_type");

                 // Create TokenEntry object with encrypted token value
                TokenEntry token = new TokenEntry(tokenId, name, service, encryptedTokenWithIV, expirationDate, metadataJson, tokenType);
                tokenList.add(token);
            }
        } catch (SQLException e) {
            System.err.println("Error retrieving all tokens: " + e.getMessage());
            throw e;
        } catch (IllegalArgumentException e) {
            System.err.println("Error creating TokenEntry from database data: " + e.getMessage());
            throw new GeneralSecurityException("Data integrity issue when creating TokenEntry.", e);
        }
        return tokenList;
    }

    /**
     * Updates an existing TokenEntry in the database.
     * The token is identified by its ID. This method takes a TokenEntry object
     * which should contain the ID of the token to update and the new values.
     * @param token The TokenEntry object with updated data.
     * @return true if the token was updated, false if not found.
     * @throws SQLException if a database access error occurs.
     */
    public static boolean updateToken(TokenEntry token) throws SQLException {
        if (token.getId() <= 0) {
            System.err.println("Cannot update token: TokenEntry object must have a valid ID.");
            return false;
        }
        String sql = "UPDATE tokens SET name = ?, service = ?, token_value = ?, expiration_date = ?, metadata = ?, token_type = ? WHERE id = ?";
        int rowsAffected = 0;

        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, token.getName());
            if (token.getService() != null) {
                pstmt.setString(2, token.getService());
            } else {
                pstmt.setNull(2, java.sql.Types.VARCHAR);
            }
            pstmt.setString(3, token.getEncryptedTokenWithIV()); // Use the encrypted value from the object

            if (token.getExpirationDate() != null) {
                pstmt.setLong(4, token.getExpirationDate().getEpochSecond());
            } else {
                pstmt.setNull(4, java.sql.Types.INTEGER);
            }

            if (token.getMetadataJson() != null) {
                pstmt.setString(5, token.getMetadataJson());
            } else {
                pstmt.setNull(5, java.sql.Types.VARCHAR);
            }

            pstmt.setString(6, token.getTokenType());
            pstmt.setInt(7, token.getId()); // Set the ID for the WHERE clause

            rowsAffected = pstmt.executeUpdate();

            if (rowsAffected > 0) {
                System.out.println("Token with ID " + token.getId() + " updated successfully.");
            } else {
                System.out.println("No token found with ID " + token.getId() + " for update.");
            }

        } catch (SQLException e) {
            System.err.println("Error updating token: " + e.getMessage());
            throw e;
        }
        return rowsAffected > 0;
    }

    /**
     * Deletes a TokenEntry from the database by its ID.
     * @param id The ID of the token to delete.
     * @return true if the token was deleted, false if not found.
     * @throws SQLException if a database access error occurs.
     */
    public static boolean deleteToken(int id) throws SQLException {
        String sql = "DELETE FROM tokens WHERE id = ?";
        int rowsAffected = 0;

        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, id);

            rowsAffected = pstmt.executeUpdate();

            if (rowsAffected > 0) {
                System.out.println("Token with ID " + id + " deleted successfully.");
            } else {
                System.out.println("No token found with ID " + id + " for deletion.");
            }

        } catch (SQLException e) {
            System.err.println("Error deleting token: " + e.getMessage());
            throw e;
        }
        return rowsAffected > 0;
    }

    /**
      * Retrieves all expired TokenEntry objects from the database.
      * A token is considered expired if its expiration_date is not null
      * and the current time is after the expiration_date.
      * @return A List of expired TokenEntry objects, or an empty list.
      * @throws SQLException if a database access error occurs.
      * @throws GeneralSecurityException if a cryptographic error occurs during object creation (unlikely here).
      */
    public static List<TokenEntry> getExpiredTokens() throws SQLException, GeneralSecurityException {
        String sql = "SELECT id, name, service, token_value, expiration_date, metadata, token_type FROM tokens WHERE expiration_date IS NOT NULL AND expiration_date < ?";
        List<TokenEntry> expiredTokenList = new ArrayList<>();
        long currentTimestamp = Instant.now().getEpochSecond(); // Get current Unix timestamp

        try (Connection conn = connect();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setLong(1, currentTimestamp);

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                        int tokenId = rs.getInt("id");
                        String name = rs.getString("name");
                        String service = rs.getString("service");
                        String encryptedTokenWithIV = rs.getString("token_value");
                        // We know expiration_date is NOT NULL here due to the WHERE clause
                        Instant expirationDate = Instant.ofEpochSecond(rs.getLong("expiration_date"));
                        String metadataJson = rs.getString("metadata");
                        String tokenType = rs.getString("token_type");

                        // Create TokenEntry object with encrypted token value
                        TokenEntry token = new TokenEntry(tokenId, name, service, encryptedTokenWithIV, expirationDate, metadataJson, tokenType);
                        expiredTokenList.add(token);
                }
            }
        } catch (SQLException e) {
            System.err.println("Error retrieving expired tokens: " + e.getMessage());
            throw e;
        } catch (IllegalArgumentException e) {
                System.err.println("Error creating TokenEntry from database data: " + e.getMessage());
                throw new GeneralSecurityException("Data integrity issue when creating TokenEntry.", e);
        }
        return expiredTokenList;
    }

    // Note: The main method from previous examples is omitted here for brevity
    // but is crucial for testing and demonstrating the usage of these methods.
    // You would include it in your DatabaseManager.java file for testing.
}