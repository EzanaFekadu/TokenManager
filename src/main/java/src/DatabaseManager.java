package src.main.java.src;
import java.sql.*;

public class DatabaseManager {
    private static final String DATABASE_URL = "jdbc:sqlite:token_management.db";

    public static Connection connect() throws SQLException {
        return DriverManager.getConnection(DATABASE_URL);
    }

    public static void createTokensTable() {
        String sql = "CREATE TABLE IF NOT EXISTS tokens (" +
                        "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                        "name TEXT NOT NULL," +
                        "service TEXT," +
                        "token_value TEXT NOT NULL," +
                        "expiration_date INTEGER," +
                        "metadata TEXT," +
                        "token_type TEXT" +
                        ");";
        try (Connection conn = connect(); Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void insertToken(TokenEntry token) {
        String sql = "INSERT INTO tokens (name, service, token_value, expiration_date, metadata, token_type) VALUES (?, ?, ?, ?, ?, ?)";
        try (Connection conn = connect(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, token.getName());
            pstmt.setString(2, token.getService());
            pstmt.setString(3, token.getEncryptedToken());
            pstmt.setLong(4, token.getExpirationDate().getEpochSecond());
            pstmt.setString(5, token.getMetadataJson());
            pstmt.setString(6, token.getTokenType());
            pstmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static ResultSet getTokenById(int id) throws SQLException {
        String sql = "SELECT * FROM tokens WHERE id = ?";
        Connection conn = connect();
        PreparedStatement pstmt = conn.prepareStatement(sql);
        pstmt.setInt(1, id);
        return pstmt.executeQuery(); // Caller must close ResultSet and Connection
    }
}