package com.bushidowallet.core.crypto.symmetric.key;

import com.bushidowallet.core.crypto.symmetric.aes.AES;
import com.bushidowallet.core.crypto.util.ByteUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.security.Security;

/**
 * Created by Jesion on 2015-11-30.
 */
public class DerivedKeyTest {

    @BeforeClass
    public static void init ()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testGenerate() throws Exception {

        final String password = "This is my password that together with salt will be an input to symmetric key derivation. In the future we will change this to user's biometric finger print";
        final String saltText = "787651234";
        final String textToEncrypt = "This is text";
        final DerivedKey key = new DerivedKey(password, saltText.getBytes(), 128);
        key.generate();
        final SecretKey secretKey = key.getKey();
        System.out.println("secret key generated: " + ByteUtil.toHex(secretKey.getEncoded()) + " key len: " + secretKey.getEncoded().length * 8);
        Assert.assertEquals("c819688e5d0fc99d3616ee76fc0bc057", ByteUtil.toHex(secretKey.getEncoded()));
        final AES cipher = new AES();
        final String cipherText = cipher.encrypt(textToEncrypt, secretKey);
        System.out.println("cipher text:" + cipherText);
        final String decryptedText = cipher.decrypt(cipherText, secretKey);
        Assert.assertEquals(textToEncrypt, decryptedText);
    }
}
