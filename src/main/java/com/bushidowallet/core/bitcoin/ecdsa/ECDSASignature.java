package com.bushidowallet.core.bitcoin.ecdsa;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequenceGenerator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 * Created by Jesion on 2015-04-11.
 */
public class ECDSASignature {

    public BigInteger r;

    public BigInteger s;

    public boolean compressed;

    public ECDSASignature(BigInteger r, BigInteger s, boolean compressed) {
        this.r = r;
        this.s = s;
        this.compressed = compressed;
    }

    public byte[] toDER() {
        return toDER(r, s);
    }

    private static byte[] toDER(BigInteger r, BigInteger s) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(72);
        DERSequenceGenerator seq = null;
        byte[] res = new byte[0];
        try {
            seq = new DERSequenceGenerator(bos);
            seq.addObject(new ASN1Integer(r));
            seq.addObject(new ASN1Integer(s));
            seq.close();
            res = bos.toByteArray();
            return res;
        } catch (IOException e) {

        }
        return null;
    }
}

