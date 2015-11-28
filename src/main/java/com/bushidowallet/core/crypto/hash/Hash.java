package com.bushidowallet.core.crypto.hash;

import org.bouncycastle.crypto.digests.RIPEMD160Digest;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by Jesion on 2015-01-13.
 */
public class Hash {

    private static String SHA256 = "SHA-256";
    private static String HmacSHA256 = "HmacSHA256";
    private static String HmacSHA512 = "HmacSHA512";
    private byte[] input;
    private int rounds = 50000;
    private String func = SHA256;

    public Hash(String input, int rounds, String func) {
        this(input.getBytes());
        this.rounds = rounds;
        this.func = func;
    }

    public Hash(byte[] input) {

        this.input = input;
    }

    public Hash(String input) {
        this(input.getBytes());
    }

    public byte[] hash() throws Exception {
        if (func.equals(SHA256)) {
            return sha256Hash(rounds);
        } else if (func.equals(HmacSHA256)) {
            return hmacHash(rounds);
        } else {
            throw new Error("Hashing function not supported");
        }
    }

    private byte[] hmacHash(int rounds) throws Exception {
        final SecretKeySpec key = new SecretKeySpec(input, HmacSHA256);
        final Mac mac = Mac.getInstance(HmacSHA256);
        mac.init(key);
        byte[] last = input;
        for (int i = 1; i <= rounds; i++) {
            last = mac.doFinal(last);
        }
        return last;
    }

    /**
     * Used to generate a maser's key hash (using "Bitcoin seed" string as key)
     *
     * @param keyStr - hashing key
     * @return
     * @throws Exception
     */
    public byte[] getHmacSHA512(String keyStr) throws Exception {
        final SecretKeySpec key = new SecretKeySpec(keyStr.getBytes(), HmacSHA512);
        final Mac mac = Mac.getInstance(HmacSHA512, "BC");
        mac.init(key);
        return mac.doFinal(this.input);
    }

    public byte[] getHmacSHA256(byte[] keyBytes) throws Exception {
        final SecretKeySpec key = new SecretKeySpec(keyBytes, HmacSHA256);
        final Mac mac = Mac.getInstance(HmacSHA256, "BC");
        mac.init(key);
        return mac.doFinal(this.input);
    }

    private byte[] sha256Hash(int rounds) throws Exception {
        final MessageDigest md = MessageDigest.getInstance(SHA256);
        byte[] last = null;
        for (int i = 1; i <= rounds; i++) {
            md.update(last == null ? input : last);
            last = md.digest();
        }
        return last;
    }

    /**
     * BIP32 Extended Key Public hash
     */
    public byte[] keyHash()
    {
        byte[] ph = new byte[20];
        try {
            byte[] sha256 = MessageDigest.getInstance(SHA256).digest(input);
            RIPEMD160Digest digest = new RIPEMD160Digest();
            digest.update(sha256, 0, sha256.length);
            digest.doFinal(ph, 0);
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return ph;
    }

    public byte[] sha256() {
        byte[] out = new byte[0];
        try {
            out = MessageDigest.getInstance(SHA256).digest(input);
        } catch (NoSuchAlgorithmException e) {

        }
        return out;
    }

    /**
     * Used by Base58 with Checksum encoding for extended keys
     */
    public static byte[] hash (byte[] data, int offset, int len) {
        try {
            MessageDigest a = MessageDigest.getInstance(SHA256);
            a.update(data, offset, len);
            return a.digest(a.digest());
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] hash(byte[] data) {
        return hash(data, 0, data.length);
    }
}
