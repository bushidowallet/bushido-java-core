package com.bushidowallet.core.bitcoin.script;

import com.bushidowallet.core.bitcoin.Address;
import com.bushidowallet.core.bitcoin.bip32.ECKey;
import com.bushidowallet.core.crypto.util.ByteUtil;
import org.junit.Assert;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by Jesion on 2015-03-26.
 */
public class ScriptTest {

    /**
     * 2 of 3 multisig output script test
     */

    @Test
    public void testBuildMultisigOut() throws Exception {

        List<ECKey> keys = new ArrayList<ECKey>();

        ECKey key1 = new ECKey(ByteUtil.fromHex("0205ee08426b39d1e24db8be38aba6b236fdd8645b63031fe943b64491b1c3bcd6"), true, false);
        ECKey key2 = new ECKey(ByteUtil.fromHex("026f108d6bd1257cb8cc95f2880e470daad5ad97b80d559cd9b818b82bc33b83d4"), true, false);
        ECKey key3 = new ECKey(ByteUtil.fromHex("0398c2e95d671f87ad47a3732bf764bd3cd9ab199fe4e538346766db2fb795ab6c"), true, false);

        keys.add(key1);
        keys.add(key2);
        keys.add(key3);

        int treshold = 2;

        Script multisigOut = Script.buildMultisigOut(keys, treshold);

        Assert.assertNotNull(multisigOut);
        Assert.assertEquals(multisigOut.getChunks().size(), 6);
        Assert.assertTrue(multisigOut.isMultiSigOut());

        byte[] bytes = multisigOut.getBytes();
        String scriptHex = ByteUtil.toHex(bytes);

        System.out.println("Multisig output script generated (hex):" + scriptHex);

        Assert.assertEquals(scriptHex, "52210205ee08426b39d1e24db8be38aba6b236fdd8645b63031fe943b64491b1c3bcd621026f108d6bd1257cb8cc95f2880e470daad5ad97b80d559cd9b818b82bc33b83d4210398c2e95d671f87ad47a3732bf764bd3cd9ab199fe4e538346766db2fb795ab6c53ae");

        Address address = new Address(multisigOut);

        System.out.println("Multisig address created from script:" + address.toString());

        Assert.assertEquals(address.toString(), "3Lk2q3HN7gYT3TRGzBbD1w4FKGKVrGqdBe");
    }

    @Test
    public void testFromString() throws Exception {

        String str = "OP_DUP OP_HASH160 20 0x88d9931ea73d60eaf7e5671efc0552b912911f2a OP_EQUALVERIFY OP_CHECKSIG";

        Script script = Script.fromString(str);

        Assert.assertNotNull(script);
        Assert.assertEquals(script.getChunks().size(), 5);
        Assert.assertEquals(script.getChunks().get(0).opcode.value, 118);
        Assert.assertNull(script.getChunks().get(0).bytes);
        Assert.assertEquals(script.getChunks().get(1).opcode.value, 169);
        Assert.assertNull(script.getChunks().get(1).bytes);
        Assert.assertEquals(script.getChunks().get(2).opcode.value, 20);
        Assert.assertNotNull(script.getChunks().get(2).bytes);
        Assert.assertEquals(script.getChunks().get(2).bytes.length, 20);
        Assert.assertEquals(script.getChunks().get(3).opcode.value, 136);
        Assert.assertNull(script.getChunks().get(3).bytes);
        Assert.assertEquals(script.getChunks().get(4).opcode.value, 172);
        Assert.assertNull(script.getChunks().get(4).bytes);
        Assert.assertTrue(script.isPublicKeyHashOut());
        Assert.assertFalse(script.isMultiSigOut());

        String scriptHex = ByteUtil.toHex(script.getBytes());

        System.out.println("scriptHex: " + scriptHex);
    }

    @Test
    public void testFromBytes() throws Exception {

        String scriptHex = "76a91488d9931ea73d60eaf7e5671efc0552b912911f2a88ac";

        byte[] bytes = ByteUtil.fromHex(scriptHex);

        Script script = Script.fromBytes(bytes);

        Assert.assertNotNull(script);
        Assert.assertEquals(script.getChunks().size(), 5);
        Assert.assertEquals(script.getChunks().get(0).opcode.value, 118);
        Assert.assertNull(script.getChunks().get(0).bytes);
        Assert.assertEquals(script.getChunks().get(1).opcode.value, 169);
        Assert.assertNull(script.getChunks().get(1).bytes);
        Assert.assertEquals(script.getChunks().get(2).opcode.value, 20);
        Assert.assertNotNull(script.getChunks().get(2).bytes);
        Assert.assertEquals(script.getChunks().get(2).bytes.length, 20);
        Assert.assertEquals(script.getChunks().get(3).opcode.value, 136);
        Assert.assertNull(script.getChunks().get(3).bytes);
        Assert.assertEquals(script.getChunks().get(4).opcode.value, 172);
        Assert.assertNull(script.getChunks().get(4).bytes);
        Assert.assertTrue(script.isPublicKeyHashOut());
        Assert.assertFalse(script.isMultiSigOut());
    }
}
