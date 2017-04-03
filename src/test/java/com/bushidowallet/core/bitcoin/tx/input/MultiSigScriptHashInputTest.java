package com.bushidowallet.core.bitcoin.tx.input;

import com.bushidowallet.core.bitcoin.Address;
import com.bushidowallet.core.bitcoin.bip32.ECKey;
import com.bushidowallet.core.bitcoin.script.Script;
import com.bushidowallet.core.bitcoin.tx.Transaction;
import com.bushidowallet.core.bitcoin.tx.TransactionSignature;
import com.bushidowallet.core.bitcoin.tx.UTXODescriptor;
import com.bushidowallet.core.crypto.util.ByteUtil;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by Jesion on 2015-04-14.
 */
public class MultiSigScriptHashInputTest {

    @BeforeClass
    public static void init ()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    //2 - of - 3 multi signature test
    @Test
    public void testSign() throws Exception {

        ECKey key1 = ECKey.ECKeyParser.parse("KwF9LjRraetZuEjR8VqEq539z137LW5anYDUnVK11vM3mNMHTWb4");
        ECKey key2 = ECKey.ECKeyParser.parse("L4PqnaPTCkYhAqH3YQmefjxQP6zRcF4EJbdGqR8v6adtG9XSsadY");
        ECKey key3 = ECKey.ECKeyParser.parse("L4CTX79zFeksZTyyoFuPQAySfmP7fL3R41gWKTuepuN7hxuNuJwV");

        List<ECKey> pub = new ArrayList<ECKey>();
        ECKey pub1 = new ECKey(key1.getPublic(), key1.isCompressed(), false);
        ECKey pub2 = new ECKey(key2.getPublic(), key2.isCompressed(), false);
        ECKey pub3 = new ECKey(key3.getPublic(), key3.isCompressed(), false);
        pub.add(pub1);
        pub.add(pub2);
        pub.add(pub3);

        Address address = new Address("33zbk2aSZYdNbRsMPPt6jgy6Kq1kQreqeb");

        List<UTXODescriptor> utxos = new ArrayList<UTXODescriptor>();
        //construct utxo that has been sent to a multisig address that we hold keys for
        UTXODescriptor utxo = new UTXODescriptor();
        utxo.script = Script.fromAddress(address).toString();
        utxo.outputIndex = 0;
        utxo.satoshis = 1000000;
        utxo.txId = "66e64ef8a3b384164b78453fa8c8194de9a473ba14f89485a0e433699daec140";
        utxos.add(utxo);

        Transaction tx = new Transaction();
        tx.from(utxos, pub, 2);
        tx.to("1ENQmzee9AGMPeL2nwJTFtQ5Zdnp1KQEJQ", 1000000);

        MultiSigScriptHashInput input = (MultiSigScriptHashInput) tx.inputs.get(0);
        int signatures = input.countSignatures();
        int missingSignatures = input.countMissingSignatures();

        Assert.assertEquals(0, signatures);
        Assert.assertEquals(2, missingSignatures);
        Assert.assertEquals(3, input.publicKeysWithoutSignature().size());
        Assert.assertFalse(tx.isFullySigned());

        tx.sign(key1, TransactionSignature.SIGHASH_ALL);

        signatures = input.countSignatures();
        missingSignatures = input.countMissingSignatures();
        Assert.assertEquals(1, signatures);
        Assert.assertEquals(1, missingSignatures);
        Assert.assertEquals(2, input.publicKeysWithoutSignature().size());
        Assert.assertFalse(tx.isFullySigned());

        tx.sign(key2, TransactionSignature.SIGHASH_ALL);

        signatures = input.countSignatures();
        missingSignatures = input.countMissingSignatures();
        Assert.assertEquals(2, signatures);
        Assert.assertEquals(0, missingSignatures);
        Assert.assertEquals(1, input.publicKeysWithoutSignature().size());
        Assert.assertTrue(tx.isFullySigned());
    }

    //Test to cover Liwl use case

    private static final String formatStringAdd0(String str, int strLength) {
        while (str.length() < strLength) {
            str = "0" + str;
        }
        return str;
    }

    private static ECKey generateKey() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDsA", new org.bouncycastle.jce.provider.BouncyCastleProvider());
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
            keyGen.initialize(ecSpec, new SecureRandom());
            KeyPair generateKeyPair = keyGen.generateKeyPair();

            BCECPrivateKey private1 = (BCECPrivateKey) generateKeyPair.getPrivate();
            BCECPublicKey public1 = (BCECPublicKey) generateKeyPair.getPublic();
            String X = public1.engineGetQ().getAffineXCoord().toBigInteger().toString(16);
            String Y = public1.engineGetQ().getAffineYCoord().toBigInteger().toString(16);

            // format string to 64 length with zero in head

            String x = formatStringAdd0(X, 64);
            String y = formatStringAdd0(Y, 64);

            // public key string
            String publicKeyStr = "04" + x + y;

            // set public key begin with 04
            return new ECKey(private1.getS().toByteArray(), false, true);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // test for 2-of-3 multi signature transaction
    // address 38bPsA6ZXfRuxFD7efVXTkQd69422uzD4B -> 1EKXAAiJDntbEK3WSVW3vTcwYJ5ciJ5kSL
    // address info ref: https://blockchain.info/address/38bPsA6ZXfRuxFD7efVXTkQd69422uzD4B
    // public key list and private key list shows below
    @Test
    public void testMutilSigTx() throws Exception {

        ECKey keyOfA = generateKey();
        ECKey keyOfB = generateKey();
        ECKey keyOfC = generateKey();

        System.out.println("public key of A: " + keyOfA.getPublicHex());
        System.out.println("public key of B: " + keyOfB.getPublicHex());
        System.out.println("public key of C: " + keyOfC.getPublicHex());
        System.out.println("private key of A: " + ByteUtil.toHex(keyOfA.getPrivate()));
        System.out.println("private key of B: " + ByteUtil.toHex(keyOfB.getPrivate()));
        System.out.println("private key of C: " + ByteUtil.toHex(keyOfC.getPrivate()));

        List<ECKey> publicKeyList = new ArrayList<ECKey>(3);
        publicKeyList.add(keyOfA);
        publicKeyList.add(keyOfB);
        publicKeyList.add(keyOfC);

        Transaction tx = new Transaction();
        UTXODescriptor utxoDescriptor = new UTXODescriptor();
        utxoDescriptor.script = Script.buildScriptHashOut(Script.buildMultisigOut(publicKeyList, 2)).toString();
        utxoDescriptor.outputIndex = 0;
        utxoDescriptor.txId = "ac89b280cc21854b82b4cc111a0e6c0d10315117b6001e3f4f3af3d2f7b2fd53";
        utxoDescriptor.satoshis = (long) 2304;

        List<UTXODescriptor> utxoDescriptors = new ArrayList<UTXODescriptor>(1);
        utxoDescriptors.add(utxoDescriptor);
        tx.from(utxoDescriptors, publicKeyList, 2);

        tx.to("1EKXAAiJDntbEK3WSVW3vTcwYJ5ciJ5kSL", 1000);

        List<ECKey> privateKeyList = new ArrayList<ECKey>(2);
        privateKeyList.add(keyOfB);
        privateKeyList.add(keyOfC);

        tx.sign(privateKeyList);

        boolean fullySigned = tx.isFullySigned();

        Assert.assertTrue(fullySigned);
    }
}
