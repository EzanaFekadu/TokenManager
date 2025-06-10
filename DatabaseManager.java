import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public class DatabaseManager {

    // Database URL - points to the SQLite file. It will be created if it doesn't exist.
    private static final String DATABASE_URL = "jdbc:sqlite:token_management.db";

    /**
     * Connects to the SQLite database.
     * If the database file does not exist, it will be created.
     * @return A Connection object
     */
    public static Connection connect() {
        Connection conn = null;
        try {
            // Load the SQLite driver (this is often done automatically in modern JDBC, but good practice)
            // Class.forName("org.sqlite.JDBC"); // Usually not needed explicitly with modern JDBC

            // Create a connection to the database
            conn = DriverManager.getConnection(DATABASE_URL);

            System.out.println("Connection to SQLite has been established.");

        } catch (SQLException e) {
            System.err.println("Database connection error: " + e.getMessage());
            // In the future we might want to log this error or handle it differently
        }
        return conn;
    }

    /**
     * Creates the 'tokens' table if it does not exist.
     */
    public static void createTokensTable() {
        // SQL statement for creating a new table
        String sql = "CREATE TABLE IF NOT EXISTS tokens (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                    "name TEXT NOT NULL," +
                    "service TEXT," +
                    "token_value TEXT NOT NULL," +
                    "expiration_date INTEGER," + // Storing as Unix timestamp
                    "metadata TEXT," +           // Storing metadata as JSON string
                    "token_type TEXT" +
                ");";

        try (Connection conn = connect();
            Statement stmt = conn.createStatement()) {

            // Execute the CREATE TABLE statement
            stmt.execute(sql);
            System.out.println("Table 'tokens' checked/created successfully.");

        } catch (SQLException e) {
            System.err.println("Error creating table: " + e.getMessage());
        }
    }

    // Main method for testing purposes
    public static void main(String[] args) {
        // Test the connection
        try (Connection conn = connect()) {
            if (conn != null) {
                System.out.println("Successfully connected to the database.");
            } else {
                System.out.println("Failed to connect to the database.");
            }
        } catch (SQLException e) {
            System.err.println("Error closing test connection: " + e.getMessage());
        }

        // Test creating the table
        createTokensTable();
    }
}