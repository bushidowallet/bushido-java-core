package com.bushidowallet.core.bitcoin.tx;

import com.bushidowallet.core.bitcoin.Address;
import com.bushidowallet.core.bitcoin.bip32.*;
import com.bushidowallet.core.bitcoin.script.Script;
import com.bushidowallet.core.crypto.util.ByteUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.Security;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by Jesion on 2015-03-30.
 */
public class HDKeyMultisigTest {

    private boolean compressedKeys = true;

    @BeforeClass
    public static void init ()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void create2of3MultisigAddressFromHDKeys() throws Exception {

        //first lets crate 3 key pairs with different entropies to simulate they belong to different wallets
        String entropy1 = "By the end of the 12th century, samurai became almost entirely synonymous with bushi";
        String entropy2 = "Some clans were originally formed by farmers who had taken up arms to protect themselves from the Imperial magistrates";
        String entropy3 = "Over time, powerful samurai clans became warrior nobility";

        List<ExtendedKey> keyPairs = new ArrayList<ExtendedKey>();
        keyPairs.add(derive(getRootKey(entropy1)));
        keyPairs.add(derive(getRootKey(entropy2)));
        keyPairs.add(derive(getRootKey(entropy3)));

        //splitting up private keys from their public brothers
        List<ECKey> pubKeys = new ArrayList<ECKey>();
        for (int i = 0; i < keyPairs.size(); i++) {
            pubKeys.add(new ECKey(keyPairs.get(i).getPublic(), compressedKeys, false));
        }

        //building up 2 of 3 multisig output script
        int treshold = 2;
        Script multisigOut = Script.buildMultisigOut(pubKeys, treshold);

        Assert.assertNotNull(multisigOut);
        Assert.assertEquals(multisigOut.getChunks().size(), 6);
        Assert.assertTrue(multisigOut.isMultiSigOut());

        byte[] bytes = multisigOut.getBytes();
        String scriptHex = ByteUtil.toHex(bytes);

        System.out.println("Multisig output script generated (hex):" + scriptHex);

        //constructing an address
        Address address = new Address(multisigOut);

        System.out.println("Multisig address created from script:" + address.toString());

        Assert.assertEquals(address.toString(), "3QEeC9xQPaPwYaC6hg9jzV3h53u5KFhbXy");
    }

    private ExtendedKey getRootKey(String entropy) throws Exception {

        byte[] passphraseHash = new Hash(entropy, 50000, "SHA-256").hash();
        byte[] keyHash = new Hash(passphraseHash).getHmacSHA512(Seed.BITCOIN_SEED);
        return new ExtendedKey(keyHash, compressedKeys);
    }

    private ExtendedKey derive(ExtendedKey root) throws Exception {
        return new Derivation(root).accountKey(0, 59, 593305);
    }

    @Test
    public void create2of3MultisigAddressFromHDKeysWithUTXO() throws Exception {

        //first lets crate 3 key pairs with different entropies to simulate they belong to different wallets
        String entropy1 = "samurai became almost entirely synonymous with bushi new";
        String entropy2 = "farmers who had taken up arms to protect themselves from the Imperial magistrates Some clans were originally formed by";
        String entropy3 = "powerful samurai clans became warrior nobility, Over time, Over time, Over time";

        List<ExtendedKey> keyPairs = new ArrayList<ExtendedKey>();
        keyPairs.add(derive(getRootKey(entropy1)));
        keyPairs.add(derive(getRootKey(entropy2)));
        keyPairs.add(derive(getRootKey(entropy3)));

        //splitting up private keys from their public brothers
        List<ECKey> pubKeys = new ArrayList<ECKey>();
        for (int i = 0; i < keyPairs.size(); i++) {
            pubKeys.add(new ECKey(keyPairs.get(i).getPublic(), compressedKeys, false));
        }

        //building up 2 of 3 multisig output script
        int treshold = 2;
        Script multisigOut = Script.buildMultisigOut(pubKeys, treshold);

        Assert.assertNotNull(multisigOut);
        Assert.assertEquals(multisigOut.getChunks().size(), 6);
        Assert.assertTrue(multisigOut.isMultiSigOut());

        byte[] bytes = multisigOut.getBytes();
        String scriptHex = ByteUtil.toHex(bytes);

        System.out.println("Multisig output script generated (hex):" + scriptHex);

        //constructing an address
        Address address = new Address(multisigOut);

        System.out.println("Multisig address created from script:" + address.toString());

        Assert.assertEquals(address.toString(), "3Egyop2xz8qoUqNUy6S1AaVnQbh8XGo6Aw");
    }
}
