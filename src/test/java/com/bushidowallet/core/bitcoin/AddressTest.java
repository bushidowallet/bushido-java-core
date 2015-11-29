package com.bushidowallet.core.bitcoin;

import org.junit.Assert;
import org.junit.Test;

/**
 * Created by Jesion on 2015-04-02.
 */
public class AddressTest {

    @Test
    public void testConstructor() throws Exception {

        String multisigAddrStr = "3Lk2q3HN7gYT3TRGzBbD1w4FKGKVrGqdBe";
        String p2pkhAddrStr = "1KxRfiqcNi2GbpdN3pzuQHgewShmeNW9g1";

        Address multisigAddr = new Address(multisigAddrStr);
        Address p2pkhAddr = new Address(p2pkhAddrStr);

        Assert.assertTrue(multisigAddr.toString().equals(multisigAddrStr));
        Assert.assertTrue(p2pkhAddr.toString().equals(p2pkhAddrStr));
    }
}
