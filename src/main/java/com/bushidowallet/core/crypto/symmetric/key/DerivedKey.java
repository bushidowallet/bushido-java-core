package com.bushidowallet.core.crypto.symmetric.key;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.KeySpec;

/**
 * Created by Jesion on 2015-11-30.
 */
public class DerivedKey {

    private String password;
    private byte[] salt;
    private int bits;
    private SecretKey key;

    public DerivedKey(String password, byte[] salt, int bits) {
        this.password = password;
        this.salt = salt;
        this.bits = bits;
    }

    public void generate() throws Exception {
        //JCE implementation, PKCS12 is the algorithm used under the hood. Giving 160 bit keys - not valid with AES - so using Sun's PBKDF2WithHmacSHA1
        //SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWITHHMACSHA1", "BC");
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 1000, bits);
        this.key = factory.generateSecret(keySpec);
    }

    public SecretKey getKey() {
        return key;
    }
}
