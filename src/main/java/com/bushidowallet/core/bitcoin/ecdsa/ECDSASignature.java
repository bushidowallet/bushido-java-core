package com.bushidowallet.core.bitcoin.ecdsa;

import com.bushidowallet.core.bitcoin.util.ByteWriter;

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

    public byte[] toBytes() {
        byte[] rnbufbase = r.toByteArray();
        byte[] rnbuf = new byte[32];
        byte[] snbuf = s.toByteArray();
        //this is basically removing the leading 0 byte, need to test that extensively, did that to be 100% in sync with bitcore.js
        System.arraycopy(rnbufbase, 1, rnbuf, 0, rnbufbase.length - 1);

        //todo: test this extensively
        boolean rneg = (rnbuf[0] & 0x80) != 0;
        boolean sneg = (snbuf[0] & 0x80) != 0;

        byte[] zero = new byte[1];
        zero[0] = 0x00;

        byte[] drn = new byte[rnbuf.length + 1];
        System.arraycopy(zero, 0, drn, 0, 1);
        System.arraycopy(rnbuf, 0, drn, 1, rnbuf.length);

        byte[] dsn = new byte[snbuf.length + 1];
        System.arraycopy(zero, 0, dsn, 0, 1);
        System.arraycopy(snbuf, 0, dsn, 1, snbuf.length);

        byte[] rbuf = rneg == true ? drn : rnbuf;
        byte[] sbuf = sneg == true ? dsn : snbuf;

        int rlength = rbuf.length;
        int slength = sbuf.length;
        int len = 2 + rlength + 2 + slength;
        int rheader = 0x02;
        int sheader = 0x02;
        int header = 0x30;

        ByteWriter writer = new ByteWriter(0);
        writer.putUInt8(header);
        writer.putUInt8(len);
        writer.putUInt8(rheader);
        writer.putUInt8(rlength);
        writer.putBytes(rbuf);
        writer.putUInt8(sheader);
        writer.putUInt8(slength);
        writer.putBytes(sbuf);

        return writer.toBytes();
    }

    //DER signature format: [30] [total len] [02] [len R] [R] [02] [len S] [S]
    public byte[] toDER() {
        return toBytes();
    }
}

