package com.bushidowallet.core.bitcoin.bip32;

import com.bushidowallet.core.TestResource;
import com.bushidowallet.core.crypto.util.ByteUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.Security;
import java.util.Arrays;

/**
 * Created by Jesion on 2015-03-10.
 */
public class ECKeySignatureTest {

    @BeforeClass
    public static void init()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testSign() throws Exception {

        JSONArray tests = new TestResource("eckeysignature.json").readObjectArray();
        for (int i = 0; i < tests.length (); i++) {
            JSONObject test = tests.getJSONObject(i);
            String wifKey = test.getString("wif");
            String message = test.getString("message");
            String signature = test.getString("signature");
            byte[] expectedSignature = ByteUtil.fromHex(signature);
            ECKey key = ECKey.ECKeyParser.parse(wifKey);
            byte[] sig = key.sign(message.getBytes());
            System.out.println("Signature created: " + ByteUtil.toHex(sig));
            Assert.assertTrue(Arrays.equals(expectedSignature, sig));
            Assert.assertTrue(key.verify(message.getBytes(), sig));
        }
    }
}
