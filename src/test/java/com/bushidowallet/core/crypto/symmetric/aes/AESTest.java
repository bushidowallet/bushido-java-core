package com.bushidowallet.core.crypto.symmetric.aes;

import com.bushidowallet.core.crypto.util.ByteUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
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
        byte[] inputText = new byte[] {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            (byte)0x88, (byte)0x99, (byte)0xaa, (byte)0xbb,
            (byte)0xcc, (byte)0xdd, (byte)0xee, (byte)0xff };
        final AESKey key = AESKey.generate(192);
        final AES cipher = new AES();
        final byte[] cipherText = cipher.encrypt(inputText, (SecretKeySpec) key.key);
        final byte[] outputText = cipher.decrypt(cipherText, (SecretKeySpec) key.key);
        Assert.assertEquals(ByteUtil.toHex(inputText), ByteUtil.toHex(outputText));
    }
}
