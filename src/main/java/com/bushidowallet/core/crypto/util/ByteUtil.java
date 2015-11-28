package com.bushidowallet.core.crypto.util;

import com.bushidowallet.core.crypto.hash.Hash;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Created by Jesion on 2015-01-14.
 */
public class ByteUtil {

    public static String toHex(byte[] bytes) {
        final StringBuffer sb = new StringBuffer();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
        }
        return sb.toString();
    }

    public static byte[] fromHex(String hex)
    {
        return Hex.decode(hex);
    }

    /**
     * Base58 - Encoding of BIP32 Keys
     */
    private static final char[] b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
    private static final int[] indexes58 = new int[128];
    static {
        for (int i = 0; i < indexes58.length; i++) {
            indexes58[i] = -1;
        }
        for (int i = 0; i < b58.length; i++) {
            indexes58[b58[i]] = i;
        }
    }

    public static String toBase58(byte[] b) {
        if (b.length == 0)
        {
            return "";
        }

        int lz = 0;
        while (lz < b.length && b[lz] == 0)
        {
            ++lz;
        }
        StringBuffer s = new StringBuffer();
        BigInteger n = new BigInteger(1, b);
        while (n.compareTo(BigInteger.ZERO) > 0)
        {
            BigInteger[] r = n.divideAndRemainder(BigInteger.valueOf(58));
            n = r[0];
            char digit = b58[r[1].intValue()];
            s.append (digit);
        }
        while (lz > 0)
        {
            --lz;
            s.append ("1");
        }
        return s.reverse().toString();
    }

    public static String toBase58WithChecksum(byte[] b) {
        byte[] cs = Hash.hash(b);
        byte[] extended = new byte[b.length + 4];
        System.arraycopy(b, 0, extended, 0, b.length);
        System.arraycopy(cs, 0, extended, b.length, 4);
        return toBase58(extended);
    }

    public static byte[] fromBase58WithChecksum(String s) throws Exception
    {
        byte[] b = fromBase58(s);
        if (b.length < 4)
        {
            throw new Exception("Too short for checksum: " + s + " l:  " + b.length);
        }
        byte[] cs = new byte[4];
        System.arraycopy(b, b.length - 4, cs, 0, 4);
        byte[] data = new byte[b.length - 4];
        System.arraycopy(b, 0, data, 0, b.length - 4);
        byte[] h = new byte[4];
        System.arraycopy(Hash.hash(data), 0, h, 0, 4);
        if (Arrays.equals(cs, h))
        {
            return data;
        }
        throw new Exception("Checksum mismatch: " + s);
    }

    public static byte[] fromBase58(String input) throws Exception {
        if (input.length() == 0) {
            return new byte[0];
        }
        byte[] input58 = new byte[input.length()];
        // Transform the String to a base58 byte sequence
        for (int i = 0; i < input.length(); ++i) {
            char c = input.charAt(i);

            int digit58 = -1;
            if (c >= 0 && c < 128) {
                digit58 = indexes58[c];
            }
            if (digit58 < 0) {
                throw new Exception("Illegal character " + c + " at " + i);
            }

            input58[i] = (byte) digit58;
        }
        // Count leading zeroes
        int zeroCount = 0;
        while (zeroCount < input58.length && input58[zeroCount] == 0) {
            ++zeroCount;
        }
        // The encoding
        byte[] temp = new byte[input.length()];
        int j = temp.length;

        int startAt = zeroCount;
        while (startAt < input58.length) {
            byte mod = divmod256(input58, startAt);
            if (input58[startAt] == 0) {
                ++startAt;
            }

            temp[--j] = mod;
        }
        // Do no add extra leading zeroes, move j to first non null byte.
        while (j < temp.length && temp[j] == 0) {
            ++j;
        }

        return copyOfRange(temp, j - zeroCount, temp.length);
    }

    private static byte divmod256(byte[] number58, int startAt) {
        int remainder = 0;
        for (int i = startAt; i < number58.length; i++) {
            int digit58 = (int) number58[i] & 0xFF;
            int temp = remainder * 58 + digit58;
            number58[i] = (byte) (temp / 256);
            remainder = temp % 256;
        }
        return (byte) remainder;
    }

    private static byte[] copyOfRange(byte[] source, int from, int to) {
        byte[] range = new byte[to - from];
        System.arraycopy(source, from, range, 0, range.length);
        return range;
    }
}
