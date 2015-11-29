package com.bushidowallet.core.crypto.symmetric.aes;

import com.bushidowallet.core.crypto.util.ByteUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.Security;

/**
 * Created by Jesion on 2015-11-28.
 */
public class AESTest {

    @BeforeClass
    public static void init ()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testEncrypt() throws Exception {

        final String inputText = "This is my text to encrypt";
        final AESKey key = AESKey.generate(256);
        final AES cipher = new AES();
        final String cipherText = cipher.encrypt(inputText, key.key);
        final String outputText = cipher.decrypt(cipherText, key.key);
        System.out.println("input " + inputText + " cipher text: " + cipherText + " key: " + ByteUtil.toHex(key.key.getEncoded()) + " output " + outputText);
        Assert.assertEquals(inputText, outputText);
    }
}
