package com.bushidowallet.core.bitcoin.tx.input;

import com.bushidowallet.core.bitcoin.Address;
import com.bushidowallet.core.bitcoin.bip32.ECKey;
import com.bushidowallet.core.bitcoin.script.Script;
import com.bushidowallet.core.bitcoin.tx.Transaction;
import com.bushidowallet.core.bitcoin.tx.TransactionSignature;
import com.bushidowallet.core.bitcoin.tx.UTXODescriptor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.Security;
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
}
