package com.bushidowallet.core.crypto.symmetric.aes;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by Jesion on 2015-11-28.
 */
public class AES {

    private Cipher cipher;

    public AES() throws Exception {
        this.cipher = Cipher.getInstance("AES/ECB/NoPadding", "BC");
    }

    public byte[] encrypt(byte[] input, SecretKeySpec key) throws Exception {
        byte[] cipherText = new byte[input.length];
        cipher.init(Cipher.ENCRYPT_MODE, key);
        int ctLength = cipher.update(input, 0, input.length, cipherText, 0);
        ctLength += cipher.doFinal(cipherText, ctLength);
        return cipherText;
    }

    public byte[] decrypt(byte[] cipherText, SecretKeySpec key) throws Exception {
        int ctLength = cipherText.length;
        byte[] output = new byte[ctLength];
        cipher.init(Cipher.DECRYPT_MODE, key);
        int ptLength = cipher.update(cipherText, 0, ctLength, output, 0);
        ptLength += cipher.doFinal(output, ptLength);
        return output;
    }
}
