import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import java.math.BigInteger;

public class Assignment1 {
    // Password in UTF-8
    private static final String PASSWORD = "EularDaGoat18374";

    // Public modulus N which is given
    private static final String N_MOD_HEX =
        "c406136c12640a665900a9df4df63a84fc855927b729a3a106fb3f379e8e4190" +
        "ebba442f67b93402e535b18a5777e6490e67dbee954bb02175e43b6481e7563d" +
        "3f9ff338f07950d1553ee6c343d3f8148f71b4d2df8da7efb39f846ac07c8652" +
        "01fbb35ea4d71dc5f858d9d41aaa856d50dc2d2732582f80e7d38c32aba87ba9";
    private static final BigInteger E = BigInteger.valueOf(65537);

    public static void main(String[] args) throws Exception {

        // Incase of wrong command argumends
        if (args.length < 1) {
            System.err.println("Error, try: java Assignment1 <inputFilename> > <encryptionFile>");
            System.exit(1);
        }
        // <encryptionFile>
        String inputFilename = args[0];

        // Read input files of Assignment1 to be encrypted
        byte[] input = Files.readAllBytes(Paths.get(inputFilename));

        // Random Generation for salt and IV
        SecureRandom sr = new SecureRandom();

        // Generate salt and IV files (128-bit)
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        byte[] iv = new byte[16];
        sr.nextBytes(iv);

        // Get AES-256 key to hash with SHA-256 (32 bytes)
        byte[] key = deriveKey(PASSWORD, salt);

        // Pad the plaintext using 0x80 and zeros
        byte[] padded = pad(input, 16);

        // AES-256 in CBC mode encryption with NoPadding (padding done previously)
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        SecretKeySpec kSpec = new SecretKeySpec(key, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, kSpec, ivSpec);
        byte[] ciphertext = cipher.doFinal(padded);

        // Print the ciphertext hex in standard output (no whitespace, and will be redirected by user to encryption file)
        System.out.print(bytesToHex(ciphertext));

        // RSA encrypt password without Java modular exponentiation (own implementation below)
        BigInteger n = new BigInteger(N_MOD_HEX, 16);
        BigInteger pInt = new BigInteger(1, PASSWORD.getBytes(StandardCharsets.UTF_8));
        // c = p^e (mod n)
        BigInteger c = modExpon(pInt, E, n);

        // Password.txt writting (hex of c padded to modulus byte length)
        int nByteLen = (n.bitLength() + 7) / 8;
        String cHex = toFixedLengthHex(c, nByteLen);

        // Write to files
        Files.write(Paths.get("Password.txt"), cHex.getBytes(StandardCharsets.UTF_8));
        Files.write(Paths.get("Salt.txt"), bytesToHex(salt).getBytes(StandardCharsets.UTF_8));
        Files.write(Paths.get("IV.txt"), bytesToHex(iv).getBytes(StandardCharsets.UTF_8));
    }

    // H200(p || s), return 32 bytes
    // https://www.geeksforgeeks.org/java/sha-256-hash-in-java/
    private static byte[] deriveKey(String password, byte[] salt) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] pBytes = password.getBytes(StandardCharsets.UTF_8);
        byte[] concat = new byte[pBytes.length + salt.length];
        System.arraycopy(pBytes, 0, concat, 0, pBytes.length);
        System.arraycopy(salt, 0, concat, pBytes.length, salt.length);
        byte[] digest = md.digest(concat); // H1
        // H2->H200
        for (int i = 1; i < 200; i++) { 
            digest = md.digest(digest);
        }
        return digest;
    }

    // Padding 0x80 then zeros. blockSize 16 bytes
    private static byte[] pad(byte[] data, int blockSize) {
        int remainder = data.length % blockSize;
        int padLen = (remainder == 0) ? blockSize : (blockSize - remainder);
        byte[] padded = Arrays.copyOf(data, data.length + padLen);
        padded[data.length] = (byte)0x80; // first padding
        // rest are 0x00 from Arrays.copyOf
        return padded;
    }

    // Modular exponentiation modExpon, right to left binary, square and multiply
    // Using BigInteger: https://docs.oracle.com/javase/8/docs/api/java/math/BigInteger.html
    private static BigInteger modExpon(BigInteger base, BigInteger exponent, BigInteger modulus) {
        BigInteger p = BigInteger.ONE;
        BigInteger a = base.mod(modulus);
        BigInteger e = exponent;
        while (e.signum() > 0) {
            // if the LSB is 1
            if (e.testBit(0)) {
                p = p.multiply(a).mod(modulus);
            }
            e = e.shiftRight(1);
            a = a.multiply(a).mod(modulus);
        }
        return p;
    }

    // Convert BigInteger to hex padded to byteLen bytes (byteLen * 2 hex)
    private static String toFixedLengthHex(BigInteger value, int byteLen) {
        String hex = value.toString(16);
        int expected = byteLen * 2;
        if (hex.length() < expected) {
            StringBuilder sb = new StringBuilder(expected);
            for (int i = 0; i < expected - hex.length(); i++) sb.append('0');
            sb.append(hex);
            return sb.toString();
        } 
        else {
            // Incase if longer
            return hex;
        }
    }

    // Bytes to lowercase hex (with no whitespace)
    // https://mkyong.com/java/java-how-to-convert-bytes-to-hex/
    // Specifically 1. String.format %02x
    // Simple byte to hex conversion (diff: byte mask, stringbuilder change)
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}