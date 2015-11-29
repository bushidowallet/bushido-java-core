package com.bushidowallet.core.bitcoin.ecdsa;

import com.bushidowallet.core.bitcoin.bip32.ECKey;
import com.bushidowallet.core.bitcoin.bip32.Hash;
import com.bushidowallet.core.bitcoin.util.BigIntegerUtil;
import com.bushidowallet.core.crypto.util.ByteUtil;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Created by Jesion on 2015-04-11.
 */
public class ECDSA {

    private byte[] hashbuf;
    private ECKey key;
    private String endian;
    private BigInteger k = BigInteger.ZERO;

    /**
     * ECDSA constructor, takes all required params for signing or signature verification
     * If constructed for verification purpose, key is a public key only
     * If constructed for signing purpose, key contains private key
     *
     * @param hashbuf
     * @param key
     * @param endian
     */
    public ECDSA(byte[] hashbuf, ECKey key, String endian) {

        this.hashbuf = hashbuf;
        this.key = key;
        this.endian  = endian;
    }

    public ECDSASignature sign() throws Exception {
        if (isValid(true)) {
            BigInteger e = BigIntegerUtil.fromBytes(hashbuf, 16, endian);
            BigInteger d = key.getPriv();
            ECDSASignature signature = findSignature(d, e);
            return signature;
        } else {
            throw new Exception("Invalid parameters");
        }
    }

    public boolean verify(ECDSASignature signature) throws Exception {
        if (isValid(false)) {
            return !hasError(signature);
        } else {
            throw new Exception("Invalid parameters");
        }
    }

    private boolean hasError(ECDSASignature signature) {
        final BigInteger r = signature.r;
        final BigInteger s = signature.s;
        if (!(r.compareTo(BigInteger.ZERO) == 1 && r.compareTo(key.params.getN()) == -1) || !(s.compareTo(BigInteger.ZERO) == 1 && s.compareTo(key.params.getN()) == -1)) {
            //r and s not in range
            return true;
        }
        final BigInteger e = BigIntegerUtil.fromBytes(hashbuf, 16, endian);
        final BigInteger n = key.params.getN();
        final BigInteger sinv = s.modInverse(n);
        final BigInteger u1 = sinv.multiply(e).mod(n);
        final BigInteger u2 = sinv.multiply(r).mod(n);
        final ECPoint g = key.params.getG();
        final ECPoint p = ECAlgorithms.sumOfTwoMultiplies(g, u1, key.curve.getCurve().decodePoint(key.getPublic()), u2).normalize();
        if (p.isInfinity()) {
            //p is infinity
            return true;
        }
        if (p.getAffineXCoord().toBigInteger().mod(n).compareTo(r) != 0) {
            //invalid signature
            return true;
        } else {
            return false;
        }
    }

    private void deterministicK(int badrs) throws Exception {
        byte[] v = new byte[32];
        Arrays.fill(v, (byte) 0x01);
        byte[] k = new byte[32];
        byte[] x = key.getPrivate();

        byte[] zero = new byte[1];
        zero[0] = (byte) 0x00;
        byte[] one = new byte[1];
        one[0] = (byte) 0x01;

        byte[] d1 = new byte[v.length + 1 + x.length + this.hashbuf.length];
        System.arraycopy(v, 0, d1, 0, v.length);
        System.arraycopy(zero, 0, d1, v.length, 1);
        System.arraycopy(x, 0, d1, v.length + 1, x.length);
        System.arraycopy(this.hashbuf, 0, d1, v.length + 1 + x.length, hashbuf.length);

        k = new Hash(d1).getHmacSHA256(k);
        v = new Hash(v).getHmacSHA256(k);

        byte[] d2 = new byte[v.length + 1 + x.length + this.hashbuf.length];
        System.arraycopy(v, 0, d2, 0, v.length);
        System.arraycopy(one, 0, d2, v.length, 1);
        System.arraycopy(x, 0, d2, v.length + 1, x.length);
        System.arraycopy(this.hashbuf, 0, d2, v.length + 1 + x.length, hashbuf.length);

        k = new Hash(d2).getHmacSHA256(k);
        v = new Hash(v).getHmacSHA256(k);
        v = new Hash(v).getHmacSHA256(k);

        BigInteger T = BigIntegerUtil.fromBytes(v, 16, null);
        BigInteger N = key.params.getN();

        for (int i = 0; i < badrs || !(T.compareTo(N) == -1 && T.compareTo(BigInteger.ZERO) == 1); i++) {

            byte[] d3 = new byte[ v.length + 1];
            System.arraycopy(v, 0, d3, 0, v.length);
            System.arraycopy(zero, 0, d3, v.length, 1);

            k = new Hash(d3).getHmacSHA256(k);
            v = new Hash(v).getHmacSHA256(k);
            v = new Hash(v).getHmacSHA256(k);
            T = BigIntegerUtil.fromBytes(v, 16, null);
        }

        this.k = T;
    }

    private ECDSASignature findSignature(BigInteger d, BigInteger e) throws Exception {
        BigInteger N = key.params.getN();
        ECPoint G = key.params.getG();
        int badrs = 0;
        BigInteger k;
        ECPoint Q;
        BigInteger r;
        BigInteger s;
        do {
            if (this.k.equals(BigInteger.ZERO) == true || badrs > 0) {
                this.deterministicK(badrs);
            }
            badrs++;
            k = this.k;
            Q = G.multiply(k);
            Q = Q.normalize();
            r = Q.getAffineXCoord().toBigInteger().mod(N);
            s = k.modInverse(N).multiply(e.add(d.multiply(r))).mod(N);
        } while (r.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(BigInteger.ZERO) <= 0);

        s = toLowS(s);
        return new ECDSASignature(r, s, key.isCompressed());
    }

    private BigInteger toLowS(BigInteger s) {
        BigInteger x = BigIntegerUtil.fromBytes(ByteUtil.fromHex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0"), 16, null);
        if (s.compareTo(x) == 1) {
            return key.params.getN().subtract(s);
        }
        return s;
    }

    private boolean isValid(boolean forSign) {
        boolean forVerify = (hashbuf != null && hashbuf.length == 32 && key != null && endian != null);
        if (forSign) {
            return forVerify && key.hasPrivate() == true;
        }
        return forVerify;
    }
}
