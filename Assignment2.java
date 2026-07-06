import java.nio.file.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.io.IOException;
import java.math.BigInteger;
import java.io.File;

// Overall running:
// $ javac Assignment2.java
// $ java Assignment2 Assignment2.class
// (Which generates y,r,s .txt)
public class Assignment2 {
    // ALL IN HEX
    // Prime Modulus p (1024-bit prime)
    private static final String P_MOD_P = 
    "b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6edd" +
    "ef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc" +
    "8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f" +
    "47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323";
    // Generator g (1024-bit)
    private static final String GEN_G = 
    "44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2" +
    "e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e8864" +
    "1a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f5496" +
    "64bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68";
    
    // Helpers/setters
    private BigInteger x, y, p, g;
    private SecureRandom sr;
    public Assignment2() {
        p = new BigInteger(P_MOD_P, 16);
        g = new BigInteger(GEN_G, 16);
        sr = new SecureRandom();
    }

    public static void main(String[] args) throws Exception {
        // Incase of wrong command argumends
        if (args.length < 1) {
            System.err.println("Try: Assignment2 Assignment2.class");
            System.exit(1);
        }
        
        // Have the class be string, Create new eGml setter, have m be the input file
        String inputFile = args[0];
        Assignment2 eGml = new Assignment2();
        File m = new File(inputFile);

        // Generate keys
        eGml.genKeys();

        // Create signature which has m signed
        BigInteger[] signature = eGml.sign(m);

        // r is the first arg, s is second
        BigInteger r = signature[0];
        BigInteger s = signature[1];

        // Save to files
        eGml.saveToFile(eGml.y, "y.txt");
        eGml.saveToFile(r, "r.txt");
        eGml.saveToFile(s, "s.txt");

        // System.out.println(r);
        // System.out.println(s);

        // Verify if the signature is valid or not
        // Prints "Valid" or "Invalid"
        boolean validity = eGml.verify(m, r, s);
        System.out.println(validity ? "Valid" : "Invalid");
    }

    // Generate random secret key x with 0 < x < p-1
    // Compute public key y as y = g^x (mod p)
    private void genKeys() {
        BigInteger p_min_1 = p.subtract(BigInteger.ONE);
        // x in range
        do {
            x = new BigInteger(p.bitLength(), sr);
        } 
        while (x.compareTo(BigInteger.ONE) < 0 || x.compareTo(p_min_1) >= 0);
        
        y = modExpon(g, x, p);        
    }

    // Compute/get SHA-256
    // From previous assignment cut down and changed for spec
    private static byte[] computeSHA(File file) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] fileBytes = Files.readAllBytes(file.toPath());
        byte[] digest = md.digest(fileBytes);
        return digest;
    }

    // Modular exponentiation modExpon, right to left binary, square and multiply
    // Using BigInteger: https://docs.oracle.com/javase/8/docs/api/java/math/BigInteger.html
    private static BigInteger modExpon(BigInteger base, BigInteger exponent, BigInteger modulus) {
        BigInteger n = BigInteger.ONE;
        BigInteger a = base.mod(modulus);
        BigInteger e = exponent;
        while (e.signum() > 0) {
            // if the LSB is 1
            if (e.testBit(0)) {
                n = n.multiply(a).mod(modulus);
            }
            e = e.shiftRight(1);
            a = a.multiply(a).mod(modulus);
        }
        return n;
    }

    // Modular inverse modInv 
    // Using BigInteger (ref): https://www.geeksforgeeks.org/dsa/multiplicative-inverse-under-modulo-m/
    private BigInteger modInv(BigInteger a, BigInteger m) {
        BigInteger[] value = extEucGCD(a, m);
        BigInteger gcd  = value[0];
        BigInteger x = value[1];
        if(!gcd.equals(BigInteger.ONE)) {
            throw new ArithmeticException("Mod inverse does not exist");
        }
        return x.mod(m);
    }

    // Signing following from spec
    // Choose a random value k with 1 < k < p-1 and gcd(k,p-1) = 1
    // Compute r as r = gk (mod p)
    // Compute s as s = (H(m)-xr)k-1 (mod p-1) where H is the hash function SHA-256. This should use your own implementation of the extended Euclidean GCD algorithm to calculate the inverse rather than using a library method for this purpose.
    // If s=0 start over again
    // The pair (r||s) is the digital signature of m
    // Used for basic structure, learning and refactored for spec: https://ssojet.com/encryption-decryption/elgamal-variable-key-size-in-java/
    // Also utilised module notes heavily
    private BigInteger[] sign(File inputFile) throws Exception {
        byte[] hash = computeSHA(inputFile);
        BigInteger hm = new BigInteger(1, hash);
        BigInteger p_min_1 = p.subtract(BigInteger.ONE);
        BigInteger k = BigInteger.ZERO;
        BigInteger r = BigInteger.ZERO; 
        BigInteger s = BigInteger.ZERO;
        // Choose a random value k with 1 < k < p-1 and gcd(k,p-1) = 1
        while(true) {
            do {
                k = new BigInteger(p.bitLength() - 1, sr);
            } 
            while (k.compareTo(BigInteger.ONE) <= 0 || k.compareTo(p_min_1) >= 0);
        
                // gcd(k, p-1) = 1
            if (!extEucGCD(k, p_min_1)[0].equals(BigInteger.ONE)) {
                continue;
            }                    
            r = modExpon(g, k, p);
            
            // s = (H(m) - x*r) * k^(-1) mod (p-1)
            BigInteger x_r = x.multiply(r);
            BigInteger num = hm.subtract(x_r).mod(p_min_1);
            BigInteger inverseK = modInv(k, p_min_1);
            s = num.multiply(inverseK).mod(p_min_1);
            // f s=0 start over again
            if(!s.equals(BigInteger.ZERO)) {
                break;
            }
        }
        return new BigInteger[] {r,s};
    }

    // From previous assignment, way to easily call for file save
    private void saveToFile(BigInteger value, String filename) throws IOException {
        String hex = toFixedLengthHex(value);
        Files.write(Paths.get(filename), hex.getBytes());
    }

    // Ensures hex is even
    private String toFixedLengthHex(BigInteger value) {
        String hex = value.toString(16);
        if(hex.length() % 2 != 0) {
            hex = "0" + hex;
        }
        return hex;
    }

    // Extended Euclidian Algorithm in GCD
    // Utilised both module notes and references below refactored to the spec
    // https://www.geeksforgeeks.org/java/java-program-for-basic-and-extended-euclidean-algorithms-2/
    // https://stackoverflow.com/questions/27004830/how-to-write-extended-euclidean-algorithm-code-wise-in-java
    // https://introcs.cs.princeton.edu/java/99crypto/ExtendedEuclid.java.html
    // Checks if b is zero and if so the gcd = a, x = 1 and y = 0
    // Recursively calls the function to get the gcd x1 and y 1
    private BigInteger[] extEucGCD(BigInteger a, BigInteger b) {
        if(b.equals(BigInteger.ZERO)) {
            return new BigInteger[] {a, BigInteger.ONE, BigInteger.ZERO};
        }
        else {
            BigInteger[] value = extEucGCD(b, a.mod(b));
            BigInteger a1 = value[0];
            BigInteger x1 = value[1];
            BigInteger y1 = value[2];

            BigInteger x = y1;
            BigInteger y = x1.subtract(a.divide(b).multiply(y1));
            return new BigInteger[] {a1,x,y};
        }
    }
    
    // Performs verification to check if signature is valid
    // Proves that someone with private key x can generate signature (r, s) given file hash
    private boolean verify(File file, BigInteger r, BigInteger s) throws Exception {
        // 0 < r < p and 0 < s < p-1, else false
        BigInteger p_min_1 = p.subtract(BigInteger.ONE);
        if(r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(p) >= 0 || s.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(p_min_1) >= 0) {
            return false;
        }
        // 256-bit digest H(m) class file m
        byte[] hash = computeSHA(file);
        // g^H(m) (mod p) = (y^r)(r^s) (mod p)
        BigInteger hm = new BigInteger(1, hash);
        BigInteger left = modExpon(g, hm, p);
        BigInteger t1 = modExpon(y, r, p);
        BigInteger t2 = modExpon(r, s, p);
        BigInteger right = (t1.multiply(t2)).mod(p);
        return left.equals(right);
    }
}