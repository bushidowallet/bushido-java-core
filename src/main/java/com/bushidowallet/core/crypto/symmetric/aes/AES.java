package com.bushidowallet.core.crypto.symmetric.aes;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.springframework.security.crypto.codec.Base64;

/**
 * Created by Jesion on 2015-11-28.
 */
public class AES {

    private Cipher cipher;

    public AES() throws Exception {

        this.cipher = Cipher.getInstance("AES", "BC");
    }

    public String encrypt(String plainText, SecretKey secretKey)
            throws Exception {
        byte[] plainTextByte = plainText.getBytes();
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedByte = cipher.doFinal(plainTextByte);
        byte[] encryptedText = Base64.encode(encryptedByte);
        return new String(encryptedText);
    }

    public String decrypt(String encryptedText, SecretKey secretKey)
            throws Exception {
        byte[] encryptedTextByte = Base64.decode(encryptedText.getBytes());
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedByte = cipher.doFinal(encryptedTextByte);
        String decryptedText = new String(decryptedByte);
        return decryptedText;
    }
}
