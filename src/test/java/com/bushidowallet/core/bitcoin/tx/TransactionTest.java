package com.bushidowallet.core.bitcoin.tx;

import com.bushidowallet.core.bitcoin.Address;
import com.bushidowallet.core.bitcoin.bip32.ECKey;
import com.bushidowallet.core.bitcoin.bip32.Hash;
import com.bushidowallet.core.bitcoin.script.Script;
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
 * Created by Jesion on 2015-03-31.
 */
public class TransactionTest {

    private static String TX1 = "01000000015884e5db9de218238671572340b207ee85b628074e7e467096c267266baf77a4000000006a473044022013fa3089327b50263029265572ae1b022a91d10ac80eb4f32f291c914533670b02200d8a5ed5f62634a7e1a0dc9188a3cc460a986267ae4d58faf50c79105431327501210223078d2942df62c45621d209fab84ea9a7a23346201b7727b9b45a29c4e76f5effffffff0150690f00000000001976a9147821c0a3768aa9d1a37e16cf76002aef5373f1a888ac00000000";
    private static String TX1ID = "779a3e5b3c2c452c85333d8521f804c1a52800e60f4b7c3bbe36f4bab350b72c";

    @BeforeClass
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testUncheckedSerialize() throws Exception {

        byte[] tx1 = ByteUtil.fromHex(TX1);
        System.out.println("Processing tx1, bytes: " + tx1.length);

        Transaction tx = new Transaction(tx1);

        Assert.assertEquals(tx.version, 1);
        Assert.assertEquals(tx.inputs.size(), 1);
        Assert.assertEquals(ByteUtil.toHex(tx.inputs.get(0).prevTxId), "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458");
        Assert.assertEquals(tx.inputs.get(0).sequence, (long) Long.valueOf("4294967295"));
        Assert.assertEquals(tx.inputs.get(0).outputIndex, 0);
        Assert.assertEquals(ByteUtil.toHex(tx.inputs.get(0).script.getBytes()), "473044022013fa3089327b50263029265572ae1b022a91d10ac80eb4f32f291c914533670b02200d8a5ed5f62634a7e1a0dc9188a3cc460a986267ae4d58faf50c79105431327501210223078d2942df62c45621d209fab84ea9a7a23346201b7727b9b45a29c4e76f5e");
        Assert.assertEquals(tx.outputs.size(), 1);
        Assert.assertEquals(tx.outputs.get(0).satoshis, 1010000);
        Assert.assertEquals(ByteUtil.toHex(tx.outputs.get(0).script.getBytes()), "76a9147821c0a3768aa9d1a37e16cf76002aef5373f1a888ac");
        Assert.assertEquals(tx.nLockTime, 0);

        byte[] serialized = tx.uncheckedSerialize();
        System.out.println("Serialized tx1, bytes: " + serialized.length);

        Assert.assertEquals(ByteUtil.toHex(serialized), TX1);
    }

    @Test
    public void testFromUTXO() throws Exception {

        String testScript = "OP_DUP OP_HASH160 20 0x88d9931ea73d60eaf7e5671efc0552b912911f2a OP_EQUALVERIFY OP_CHECKSIG";
        String testPrevTx = "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458";
        long testAmount = 1020000;
        String receivingAddress = "1KxRfiqcNi2GbpdN3pzuQHgewShmeNW9g1";

        List<UTXODescriptor> utxos = new ArrayList<UTXODescriptor>();
        utxos.add(new UTXODescriptor(testPrevTx, 0, testScript, testAmount));

        Transaction tx = new Transaction();
        tx.from(utxos).to(receivingAddress, testAmount - 10000);

        Assert.assertEquals(0, tx.nLockTime);
        Assert.assertEquals(1, tx.version);
        Assert.assertEquals(1, tx.inputs.size());
        Assert.assertEquals(0, tx.inputs.get(0).script.getChunks().size());
        Assert.assertEquals(0, tx.inputs.get(0).outputIndex);
        Assert.assertEquals(testPrevTx, ByteUtil.toHex(tx.inputs.get(0).prevTxId));
        Assert.assertEquals(testAmount, tx.inputs.get(0).output.satoshis);
        Assert.assertEquals(testScript, tx.inputs.get(0).output.script.toString());
        Assert.assertEquals(1, tx.outputs.size());
        Assert.assertEquals(1010000, tx.outputs.get(0).satoshis);
        Assert.assertEquals("76a914cfedbbc5fc5fd9665b548a66bdade69ca5d9ce2188ac", ByteUtil.toHex(tx.outputs.get(0).script.getBytes()));
        Assert.assertEquals("OP_DUP OP_HASH160 20 0xcfedbbc5fc5fd9665b548a66bdade69ca5d9ce21 OP_EQUALVERIFY OP_CHECKSIG", tx.outputs.get(0).script.toString());
        Assert.assertEquals(1020000, tx.getInputAmount());
        Assert.assertEquals(1010000, tx.getOutputAmount());
        Assert.assertEquals(10000, tx.getFee());
        Assert.assertEquals(167, tx.estimateSize());
        Assert.assertEquals(10000, tx.estimateFee());
    }

    @Test
    public void testGetHash() throws Exception {

        Transaction tx = new Transaction(ByteUtil.fromHex(TX1));
        Assert.assertEquals(TX1ID, ByteUtil.toHex(tx.getHash()));
    }

    @Test
    public void testEmptyTx() throws Exception {

        Transaction tx = new Transaction();
        Assert.assertEquals("01000000000000000000", ByteUtil.toHex(tx.uncheckedSerialize()));
    }

    @Test
    public void testFrom() throws Exception {

        UTXODescriptor utxoDescriptor = new UTXODescriptor();
        utxoDescriptor.script = Script.fromAddress(new Address("1KxRfiqcNi2GbpdN3pzuQHgewShmeNW9g1")).toString();
        utxoDescriptor.outputIndex = 0;
        utxoDescriptor.txId = "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458";
        utxoDescriptor.satoshis = (long) 1e8;

        Assert.assertEquals("OP_DUP OP_HASH160 20 0xcfedbbc5fc5fd9665b548a66bdade69ca5d9ce21 OP_EQUALVERIFY OP_CHECKSIG", utxoDescriptor.script);
        Assert.assertEquals(100000000, utxoDescriptor.satoshis);

        Transaction tx = new Transaction();
        tx.from(utxoDescriptor);
        try {
            tx.from(utxoDescriptor);
        } catch (Exception e) {
            System.out.println("Can't add same utxo twice");
        }
        Assert.assertEquals(1, tx.inputs.size());
    }

    @Test
    public void testSerializeNoChange() throws Exception {

        UTXODescriptor utxoDescriptor = new UTXODescriptor();
        utxoDescriptor.script = Script.fromAddress(new Address("1GRgGGZuErvGiPnmFbFubDDS7SKWz6xrNu")).toString();
        utxoDescriptor.satoshis = 100000;
        utxoDescriptor.txId = "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458";
        utxoDescriptor.outputIndex = 0;
        Transaction tx = new Transaction();
        tx.from(utxoDescriptor);
        tx.to("1H6WmxpDEPX7L96FCPZzm1KPaVwZbzXrav", 50000);
        Assert.assertEquals("01000000015884e5db9de218238671572340b207ee85b628074e7e467096c267266baf77a40000000000ffffffff0150c30000000000001976a914b08cf28bbf4b393dcbdbd69fb27f3436d8392e6e88ac00000000", ByteUtil.toHex(tx.uncheckedSerialize()));
    }

    @Test
    public void testSerializeWithChange() throws Exception {

        UTXODescriptor utxoDescriptor = new UTXODescriptor();
        utxoDescriptor.script = Script.fromAddress(new Address("1GRgGGZuErvGiPnmFbFubDDS7SKWz6xrNu")).toString();
        utxoDescriptor.satoshis = 100000;
        utxoDescriptor.txId = "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458";
        utxoDescriptor.outputIndex = 0;
        Transaction tx = new Transaction();
        tx.from(utxoDescriptor);
        tx.to("1H6WmxpDEPX7L96FCPZzm1KPaVwZbzXrav", 50000);
        tx.change(new Address("1ENQmzee9AGMPeL2nwJTFtQ5Zdnp1KQEJQ"));

        Assert.assertEquals("409c0000000000001976a91492a637a6daa2be8cede265048f8fa02ddaa8111088ac", tx.outputs.get(1).toHex());
        Assert.assertEquals("01000000015884e5db9de218238671572340b207ee85b628074e7e467096c267266baf77a40000000000ffffffff0250c30000000000001976a914b08cf28bbf4b393dcbdbd69fb27f3436d8392e6e88ac409c0000000000001976a91492a637a6daa2be8cede265048f8fa02ddaa8111088ac00000000", ByteUtil.toHex(tx.uncheckedSerialize()));
    }

    @Test
    public void testSign() throws Exception {

        UTXODescriptor utxoDescriptor = new UTXODescriptor();
        utxoDescriptor.script = Script.fromAddress(new Address("1GRgGGZuErvGiPnmFbFubDDS7SKWz6xrNu")).toString();
        utxoDescriptor.satoshis = 100000;
        utxoDescriptor.txId = "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458";
        utxoDescriptor.outputIndex = 0;

        Transaction tx = new Transaction();
        tx.from(utxoDescriptor);
        tx.to("1H6WmxpDEPX7L96FCPZzm1KPaVwZbzXrav", 50000);
        tx.change(new Address("1ENQmzee9AGMPeL2nwJTFtQ5Zdnp1KQEJQ"));

        List<ECKey> keys = new ArrayList<ECKey>();
        keys.add(ECKey.ECKeyParser.parse("L1rjeUY9ffkApft853udougq6y5eT3xbyoNPcMnkpzhZUQrui9cn"));

        tx.sign(keys);
        Assert.assertTrue(tx.isFullySigned());

        String expectedSigScriptHex = "483045022100d483938898a656d783a908ba45b66433e84f81d3fbbeb24477c3d76fa3d25b4e022006607b0e9b83664d531bdebc245f2e5eb59e8a5a4b80a7e4bf83210a18d4dc280121020cb8b0a0b5e99640d502f9db76f888a46fdda112a1e272842452e58d4227d78b";

        Assert.assertEquals(expectedSigScriptHex, ByteUtil.toHex(tx.inputs.get(0).script.getBytes()));
    }

    @Test
    public void testSigHash() throws Exception {
        String messageHex = "01000000015884e5db9de218238671572340b207ee85b628074e7e467096c267266baf77a4000000001976a914a934a528778e10dccd33b741577601e51031ac9388acffffffff0250c30000000000001976a914b08cf28bbf4b393dcbdbd69fb27f3436d8392e6e88ac409c0000000000001976a91492a637a6daa2be8cede265048f8fa02ddaa8111088ac0000000001000000";
        byte[] message = ByteUtil.fromHex(messageHex);
        byte[] hash = Hash.hash(message);
        String expectedHash = "e8d985a954b90f6bff8dbb53637626037712d591b27430a47c4283c04b00bca9";
        Assert.assertEquals(expectedHash, ByteUtil.toHex(hash));
        byte[] result = ByteUtil.reverseBytes(hash);
        String resultHex = ByteUtil.toHex(result);
        //createad from a Tx, a hash which is used as a message to be signed
        //this hash is an input to ECDSA sign(), see ECDSATest.java
        Assert.assertEquals("a9bc004bc083427ca43074b291d512770326766353bb8dff6b0fb954a985d9e8", resultHex);
    }

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
    }
}