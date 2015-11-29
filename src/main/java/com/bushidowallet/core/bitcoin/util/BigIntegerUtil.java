package com.bushidowallet.core.bitcoin.util;

import com.bushidowallet.core.crypto.util.ByteUtil;

import java.math.BigInteger;

/**
 * Created by Jesion on 2015-04-12.
 */
public class BigIntegerUtil {

    public static BigInteger fromBytes(byte[] bytes, int radix, String endian) {
        byte[] bigInt = null;
        if (endian != null && endian.equals("little")) {
            bigInt = ByteUtil.reverseBytes(bytes);
        } else {
            bigInt = bytes;
        }
        return new BigInteger(ByteUtil.toHex(bigInt), radix);
    }

    public static boolean equal(BigInteger int1, BigInteger int2) {
        if (int1.compareTo(int2) == 0) {
            return true;
        }
        return false;
    }
}
