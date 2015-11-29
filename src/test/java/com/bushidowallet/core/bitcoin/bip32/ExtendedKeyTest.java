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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by Jesion on 2015-01-14.
 */
public class ExtendedKeyTest {

    @BeforeClass
    public static void init ()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testBip32UncompressedKey() throws Exception {

        boolean compressed = false;

        JSONArray tests = new TestResource("bitcoinkeyuncompressed.json").readObjectArray();
        for (int i = 0; i < tests.length (); i++)
        {
            JSONObject test = tests.getJSONObject(i);

            byte[] passphraseHash = new Hash(test.getString("passphrase"), test.getInt("rounds"), test.getString("func")).hash();
            byte[] keyHash = new Hash(passphraseHash).getHmacSHA512(Seed.BITCOIN_SEED);
            Assert.assertTrue(test.getString("keyhash").equals(ByteUtil.toHex(keyHash)));
            ExtendedKey extendedKey = new ExtendedKey(keyHash, compressed);
            String chainCode = ByteUtil.toHex(extendedKey.getChainCode());
            Assert.assertTrue(test.getString("chainCode").equals(chainCode));
            String extendedPubKey = extendedKey.serializePublic();
            Assert.assertTrue(test.getString("public").equals(extendedPubKey));
            String extendedPrivKey = extendedKey.serializePrivate();
            Assert.assertTrue(test.getString("private").equals(extendedPrivKey));
            JSONArray derived = test.getJSONArray("derived");
            List<Map<String, String>> derivedPairs = new ArrayList<Map<String, String>>();

            for (int j = 0; j < derived.length(); j++) {

                JSONObject derivedTest = derived.getJSONObject(j);
                String path = derivedTest.getString("path");
                Derivation derivation = new Derivation(extendedKey);
                ExtendedKey child = derivation.derive(path);
                Map<String, String> pair = new HashMap<String, String>();
                pair.put("path", derivedTest.getString("path"));
                pair.put("public", child.serializePublic());
                pair.put("publicHex", child.getPublicHex());
                pair.put("private", child.serializePrivate());
                pair.put("address", child.getAddress().toString());
                pair.put("wif", child.getWIF());
                derivedPairs.add(pair);
                Assert.assertTrue(derivedTest.getString("public").equals(pair.get("public")));
                Assert.assertTrue(derivedTest.getString("publicHex").equals(pair.get("publicHex")));
                Assert.assertTrue(derivedTest.getString("private").equals(pair.get("private")));
                Assert.assertTrue(derivedTest.getString("address").equals(pair.get("address")));
                Assert.assertTrue(derivedTest.getString("wif").equals(pair.get("wif")));
            }

            Assert.assertTrue(true);
        }
    }

    /**
     * Tests keys generation/derivation - compressed - Electrum compatibility
     * @throws Exception
     */
    @Test
    public void testBip32CompressedKey() throws Exception {

        boolean compressed = true;

        JSONArray tests = new TestResource("bitcoinkeycompressed.json").readObjectArray();
        for (int i = 0; i < tests.length (); i++)
        {
            JSONObject test = tests.getJSONObject(i);
            byte[] passphraseHash = new Hash(test.getString("passphrase"), test.getInt("rounds"), test.getString("func")).hash();
            byte[] keyHash = new Hash(passphraseHash).getHmacSHA512(Seed.BITCOIN_SEED);
            Assert.assertTrue(test.getString("keyhash").equals(ByteUtil.toHex(keyHash)));
            ExtendedKey extendedKey = new ExtendedKey(keyHash, compressed);
            String chainCode = ByteUtil.toHex(extendedKey.getChainCode());
            Assert.assertTrue(test.getString("chainCode").equals(chainCode));
            String extendedPubKey = extendedKey.serializePublic();
            Assert.assertTrue(test.getString("public").equals(extendedPubKey));
            String extendedPrivKey = extendedKey.serializePrivate();
            Assert.assertTrue(test.getString("private").equals(extendedPrivKey));
            ExtendedKey parsedPrivKey = ExtendedKey.parse(extendedPrivKey, compressed);
            Assert.assertTrue(extendedKey.equals(parsedPrivKey));
            ExtendedKey parsedPubKey = ExtendedKey.parse(extendedPubKey, compressed);
            Assert.assertFalse(extendedKey.equals(parsedPubKey));
            Assert.assertTrue(parsedPubKey.serializePublic().equals(extendedKey.serializePublic()));
            JSONArray derived = test.getJSONArray("derived");
            List<Map<String, String>> derivedPairs = new ArrayList<Map<String, String>>();

            for (int j = 0; j < derived.length(); j++) {

                JSONObject derivedTest = derived.getJSONObject(j);
                String path = derivedTest.getString("path");
                Derivation derivation = new Derivation(extendedKey);
                ExtendedKey child = derivation.derive(path);
                Map<String, String> pair = new HashMap<String, String>();
                pair.put("path", derivedTest.getString("path"));
                pair.put("public", child.serializePublic());
                pair.put("publicHex", child.getPublicHex());
                pair.put("private", child.serializePrivate());
                pair.put("address", child.getAddress().toString());
                pair.put("wif", child.getWIF());
                derivedPairs.add(pair);
                Assert.assertTrue(derivedTest.getString("public").equals(pair.get("public")));
                Assert.assertTrue(derivedTest.getString("publicHex").equals(pair.get("publicHex")));
                Assert.assertTrue(derivedTest.getString("private").equals(pair.get("private")));
                Assert.assertTrue(derivedTest.getString("address").equals(pair.get("address")));
                Assert.assertTrue(derivedTest.getString("wif").equals(pair.get("wif")));
            }

            Assert.assertTrue(true);
        }
    }
}
