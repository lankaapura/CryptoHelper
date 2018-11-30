import java.nio.charset.Charset;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Random;
import java.util.Base64;

public class CryptoHelper {

    private static final int SALT_SIZE = 128/8; // 128 bits
    private static final int KEY_LENGTH = 256; // 256 bits
    private static final int ITERATIONS = 10000;
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";

    public static boolean VerifyHashedPassword(String password, String expectedHash) {
        if (password == null) {
            return false;
        }

        byte[] decodedHashedPassword = Base64.getDecoder().decode(expectedHash);

        if (decodedHashedPassword.length == 0)
        {
            return false;
        }

        // Verify hashing format.
        if (decodedHashedPassword[0] != 0x01)
        {
            // Unknown format header.
            return false;
        }

        // Read hashing algorithm version.
        int prf = ReadNetworkByteOrder(decodedHashedPassword, 1);

        // Read iteration count of the algorithm.
        int iterCount = (int)ReadNetworkByteOrder(decodedHashedPassword, 5);

        // Read size of the salt.
        int saltLength = (int)ReadNetworkByteOrder(decodedHashedPassword, 9);

        byte[] salt = new byte[saltLength];
        byte[] pwdHash = new byte[decodedHashedPassword.length - 13 - saltLength];

        System.arraycopy(decodedHashedPassword, 13, salt, 0, saltLength);
        System.arraycopy(decodedHashedPassword, 13 + saltLength, pwdHash, 0, decodedHashedPassword.length - 13 - saltLength);
        
        final byte[] pwdHash2 = CryptoHelper.HashPassword(password, salt);
        final int length = pwdHash.length;

        if (length != pwdHash2.length) {
            return false;
        }

        int i = 0;
        boolean result = true;

        while ((i < length) && result) {
            result = pwdHash[i] == pwdHash2[i];
            i++;
        }

        return result;
    }

    public static byte[] HashPassword(String password, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
            SecretKeyFactory f = SecretKeyFactory.getInstance(ALGORITHM);
            return f.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {

            return null;
        }
    }

    public static String GenerateSaltedHash(String password) {

        byte[] salt = GenerateRadomSalt();
        byte[] pwdHash = CryptoHelper.HashPassword(password, salt);
        byte[] saltedHash = new byte[13 + salt.length + pwdHash.length];

        // Write format marker.
        saltedHash[0] = 0x01;

        WriteNetworkByteOrder(saltedHash, 1, 1);
        WriteNetworkByteOrder(saltedHash, 5, ITERATIONS);
        WriteNetworkByteOrder(saltedHash, 9, SALT_SIZE);

        System.arraycopy(salt, 0, saltedHash, 13, salt.length);
        System.arraycopy(pwdHash, 0, saltedHash, 13 + SALT_SIZE, pwdHash.length);

        return new String(Base64.getEncoder().encode(saltedHash));
    }

    private static void WriteNetworkByteOrder(byte[] buffer, int offset, int value) {
        buffer[offset + 0] = (byte) (value >> 24);
        buffer[offset + 1] = (byte) (value >> 16);
        buffer[offset + 2] = (byte) (value >> 8);
        buffer[offset + 3] = (byte) (value >> 0);
    }

    private static int ReadNetworkByteOrder(byte[] buffer, int offset)
    {
        return ((int)(buffer[offset + 0]) << 24)
            | ((int)(buffer[offset + 1]) << 16)
            | ((int)(buffer[offset + 2]) << 8)
            | ((int)(buffer[offset + 3]));
    }

    public static byte[] GenerateRadomSalt() {
        final Random r = new SecureRandom();
        byte[] salt = new byte[CryptoHelper.SALT_SIZE];
        r.nextBytes(salt);
        return salt;
    }
}
