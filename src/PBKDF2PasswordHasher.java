import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 * PBKDF2 Password hashing class using SHA-512
 */
class PBKDF2PasswordHasher {

    // Number of Iterations to slow down hashing
    public static final int ITERATIONS = 10000;
    // Number of Bytes in Hash, 64 * 8 bits = 512 bits
    public static final int HASH_BYTES = 64;
    // 128 bit salt key
    public static final int SALT_BYTES = 16;
    // Hashing algorithm used is PBKDF2 implementing SHA-512
    public static final String HASH_ALGORITHM = "PBKDF2WithHmacSHA512";
    // For conversion between hex string and byte array
    private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);
    // Object to store Hash and Salt, Mimics the object that would be used to save to DB (Hash, Salt)
    private static final User DATA = new User();

    /**
     * inner class for mimic DB
     */
    private static class User {
        private byte[] hash;
        private byte[] salt;

        public User() {
            hash = new byte[HASH_BYTES * 8];
            salt = new byte[SALT_BYTES * 8];
        }
    }

    /**
     * Given a password, sets the DATA object params to the passwords HASH, and generated salt
     * @param password Input password
     */
    public void createHash(String password) {
        char[] pass = password.toCharArray();
        byte[] salt = generateSalt();
        DATA.hash = hash(pass,salt,ITERATIONS,HASH_BYTES);
        DATA.salt = salt;
    }

    /**
     * Validates given password to a DATA object, in practice the DATA object is the one queried from DB
     * @param password Input password to authenticate
     * @param data User object queried from DB
     * @return Returns true if authenticated, false if passwords don't match
     */
    public boolean validatePassword(String password, User data) {
        char[] pass = password.toCharArray();
        byte[] salt = data.salt;
        byte[] hashPass = hash(pass,salt,ITERATIONS,HASH_BYTES);

        return constantEquals(hashPass,data.hash);

    }

    /**
     * Hash function using PBKDF2 algorithm
     * @param password Password as char array
     * @param salt Salt as byte array
     * @param iterations Number of Iterations
     * @param bytes Number of bytes
     * @return Returns the generated Hash
     */
    public byte[] hash(char[] password,byte[] salt, int iterations, int bytes) {
        try {
            SecretKeyFactory secret = SecretKeyFactory.getInstance(HASH_ALGORITHM);
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bytes * 8);
            return secret.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Generates a cryptographically random number, size based on SALT_BYTES CONSTANT
     * @return Returns the random salt
     */
    public byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        return salt;
    }

    /**
     * Turns array of bytes into hex string
     * @param bytes Byte array
     * @return Returns hex string
     */
    public String bytesToHex(byte[] bytes) {
        byte[] hexChars = new byte[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars, StandardCharsets.UTF_8);
    }

    /**
     * Turns hex string to byte array
     * @param hex Hex String
     * @return Returns byte array
     */
    private byte[] hexToBytes(String hex)
    {
        byte[] binary = new byte[hex.length() / 2];
        for(int i = 0; i < binary.length; i++)
        {
            binary[i] = (byte)Integer.parseInt(hex.substring(2*i, 2*i+2), 16);
        }
        return binary;
    }

    /**
     * Method for comparing byte arrays in constant time
     * @param a Byte array one
     * @param b Byte array two
     * @return Returns true if the byte arrays match, in a constant time
     */
    public boolean constantEquals(byte[] a, byte[] b) {
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }


    public static void main(String[] args) {

        PBKDF2PasswordHasher h = new PBKDF2PasswordHasher();


        // Take password as input and hash it --> store in User object, Hash and salt. User object is for imitating DB
        // HASH AND SALT OF PASSWORD IS SAVED AS USER DATA IN DB
        h.createHash("password");
        System.out.println(h.bytesToHex(DATA.hash));

        System.out.println(h.validatePassword("password",DATA));

    }



}
