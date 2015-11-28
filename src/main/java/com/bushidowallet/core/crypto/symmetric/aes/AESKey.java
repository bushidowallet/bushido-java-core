package com.bushidowallet.core.crypto.symmetric.aes;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Created by Jesion on 2015-11-28.
 */
public class AESKey {

    private static String AES = "AES";

    public int bits;

    public SecretKey key;

    public AESKey(int bits, SecretKey key) {
        this.bits = bits;
        this.key = key;
    }

    public static AESKey generate(int bits) throws Exception {
        final KeyGenerator keyGen = KeyGenerator.getInstance(AES);
        keyGen.init(bits);
        final SecretKey secretKey = keyGen.generateKey();
        return new AESKey(bits, secretKey);
    }
}
