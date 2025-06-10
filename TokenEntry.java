import java.time.Instant;

public class TokenEntry{

    private int id;
    private String name;
    private String service;
    private String tokenValue;
    private Instant expirationDate; //the expiration time for the token
    private String metadataJson; //store additional metadata in JSON format
    private String tokenType;

    public TokenEntry(String name, String service, String tokenValue, Instant expirationDate, String metadataJson, String tokenType) {
        this.name = name;
        this.service = service;
        this.tokenValue = tokenValue;
        this.expirationDate = expirationDate;
        this.metadataJson = metadataJson;
        this.tokenType = tokenType;
    }

    public TokenEntry(int id, String name, String service, String tokenValue, Instant expirationDate, String metadataJson, String tokenType) {
        this.id = id;
        this.name = name;
        this.service = service;
        this.tokenValue = tokenValue;
        this.expirationDate = expirationDate;
        this.metadataJson = metadataJson;
        this.tokenType = tokenType;
    }
    public int getId() {
        return id;
    }
    public String getName() {
        return name;
    }
    public String getService() {
        return service;
    }
    public String getTokenValue() {
        return tokenValue;
    }
    public Instant getExpirationDate() {
        return expirationDate;
    }
    public String getMetadataJson() {
        return metadataJson;
    }
    public String getTokenType() {
        return tokenType;
    }

    //Let's add the setters for the fields that might need to be updated
    //But we will probably remove them later if we want to make the class immutable
    public void setId(int id) {
        this.id = id;
    }
    public void setName(String name) {
        this.name = name;
    }
    public void setService(String service) {
        this.service = service;
    }
    public void setTokenValue(String tokenValue) {
        this.tokenValue = tokenValue;
    }
    public void setExpirationDate(Instant expirationDate) {
        this.expirationDate = expirationDate;
    }
    public void setMetadataJson(String metadataJson) {
        this.metadataJson = metadataJson;
    }
    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    //Let's use the toString method to print the object in a readable format
    //But we will change it if we're going to use it for logging
    @Override
    public String toString() {
        return "TokenEntry{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", service='" + service + '\'' +
                ", tokenValue='" + tokenValue + '\'' +
                ", expirationDate=" + expirationDate +
                ", metadataJson='" + metadataJson + '\'' +
                ", tokenType='" + tokenType + '\'' +
                '}';
    }
}