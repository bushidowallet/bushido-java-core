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

/**
 * Created by Jesion on 2015-01-13.
 */
public class HashTest {

    @BeforeClass
    public static void init ()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testPassphraseHash() throws Exception {

        JSONArray tests = new TestResource("passphrase.json").readObjectArray();
        for (int i = 0; i < tests.length (); ++i)
        {
            JSONObject test = tests.getJSONObject(i);
            byte[] hash = new Hash(test.getString("passphrase"), test.getInt("rounds"), test.getString("func")).hash();
            Assert.assertTrue(test.getString("hash").equals(ByteUtil.toHex(hash)));
        }
    }

    @Test
    public void testKeyHash() throws Exception {

        JSONArray tests = new TestResource("bitcoinkeycompressed.json").readObjectArray();
        for (int i = 0; i < tests.length (); ++i)
        {
            JSONObject test = tests.getJSONObject(i);
            byte[] passphraseHash = new Hash(test.getString("passphrase"), test.getInt("rounds"), test.getString("func")).hash();
            byte[] keyHash = new Hash(passphraseHash).getHmacSHA512("Bitcoin seed");
            Assert.assertTrue(test.getString("keyhash").equals(ByteUtil.toHex(keyHash)));
        }
    }
}



