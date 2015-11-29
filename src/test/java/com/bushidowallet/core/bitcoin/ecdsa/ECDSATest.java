package com.bushidowallet.core.bitcoin.ecdsa;

import com.bushidowallet.core.bitcoin.bip32.ECKey;
import com.bushidowallet.core.bitcoin.util.BigIntegerUtil;
import com.bushidowallet.core.crypto.util.ByteUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;
import java.security.Security;

/**
 * Created by Jesion on 2015-04-11.
 */
public class ECDSATest {

    @BeforeClass
    public static void init ()
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testSign() throws Exception {
        //tx signing hash, used as a message
        String hashbufHex = "a9bc004bc083427ca43074b291d512770326766353bb8dff6b0fb954a985d9e8";
        //key used to sign, contains private key (big number)
        ECKey key = ECKey.ECKeyParser.parse("L1rjeUY9ffkApft853udougq6y5eT3xbyoNPcMnkpzhZUQrui9cn");

        ECDSASignature signature = new ECDSA(ByteUtil.fromHex(hashbufHex), key, "little").sign();

        //we are using a key that is compressed
        Assert.assertEquals(true, signature.compressed);

        //test vector r value: 96122799104480063949910401630073779459529981243145212477597930766576003472206
        BigInteger expectedR = BigIntegerUtil.fromBytes(ByteUtil.fromHex("d483938898a656d783a908ba45b66433e84f81d3fbbeb24477c3d76fa3d25b4e"), 16, null);
        //test vector s value: 2884343718335691681268558098888226414792197237717938429255727702061400513576
        BigInteger expectedS = BigIntegerUtil.fromBytes(ByteUtil.fromHex("06607b0e9b83664d531bdebc245f2e5eb59e8a5a4b80a7e4bf83210a18d4dc28"), 16, null);

        Assert.assertTrue(BigIntegerUtil.equal(expectedR, signature.r));
        Assert.assertTrue(BigIntegerUtil.equal(expectedS, signature.s));
    }
}
