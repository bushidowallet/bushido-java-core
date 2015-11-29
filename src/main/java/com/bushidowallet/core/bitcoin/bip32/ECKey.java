package com.bushidowallet.core.bitcoin.bip32;

import com.bushidowallet.core.crypto.util.ByteUtil;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.util.Arrays;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

/**
 * Created by Jesion on 2015-01-14.
 *
 * Elliptic Curve Key represents a pair of keys actually,
 * - Private which is a BigInteger
 * - Public which is an Elliptic Curve multiplication of private
 */
public class ECKey {

    public static final X9ECParameters curve = SECNamedCurves.getByName("secp256k1");
    public static final ECDomainParameters params = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH());

    private BigInteger priv;
    private byte[] pub;
    private byte[] pubKeyHash;
    private boolean compressed;

    //l is unsigned byte[] - coming from left part of bitcoin key hash
    //it can be converted to BigInt and saved as private master key
    public ECKey(byte[] l, boolean compressed) {

        this(l, compressed, true);
    }

    //ECKey constructor with parent argument for key derivation
    public ECKey(byte[] l, ECKey parent) {

        if (parent.hasPrivate()) {
            this.priv = new BigInteger(1, l).add(parent.priv).mod(curve.getN());
            setPub(parent.compressed, true, null);
        } else {
            throw new Error("Support derived ECKey with public key only");
        }
    }

    //bytes is either coming from left part of bitcoin key hash
    //it can be converted to BigInt and saved as private master key
    //isPrivate is set to true in this case,
    //otherwise its a public key only
    public ECKey(byte[] bytes, boolean compressed, boolean isPrivate) {
        if (isPrivate == true) {
            this.priv = new BigInteger (1, bytes);
            setPub(compressed, true, null);
        } else {
            setPub(compressed, false, bytes);
        }
    }

    public byte[] sign(byte[] message) throws Exception
    {
        if (priv == null) {
            throw new Exception("Unable to sign");
        }
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        signer.init(true, new ECPrivateKeyParameters(priv, params));
        BigInteger[] signature = signer.generateSignature(message);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        DERSequenceGenerator seqGen = new DERSequenceGenerator(outputStream);
        seqGen.addObject(new ASN1Integer(signature[0]));
        seqGen.addObject(new ASN1Integer(signature[1]));
        seqGen.close();
        return outputStream.toByteArray();
    }

    public boolean verify(byte[] message, byte[] signature) throws Exception
    {
        ASN1InputStream asn1 = new ASN1InputStream(signature);
        ECDSASigner signer = new ECDSASigner();
        //not for signing...
        signer.init(false, new ECPublicKeyParameters(curve.getCurve().decodePoint(pub), params));
        DLSequence seq = (DLSequence) asn1.readObject();
        BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getPositiveValue();
        BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getPositiveValue();
        return signer.verifySignature(message, r, s);
    }

    public byte[] getPrivate()
    {
        if (hasPrivate()) {
            byte[] p = priv.toByteArray();
            if (p.length != 32) {
                byte[] tmp = new byte[32];
                System.arraycopy(p, Math.max(0, p.length - 32), tmp, Math.max(0, 32 - p.length), Math.min(32, p.length));
                p = tmp;
            }
            return p;
        }
        return null;
    }

    public BigInteger getPriv() {
        return priv;
    }

    public String getWIF() throws Exception {
        return ByteUtil.toBase58(getWIFBytes());
    }

    public boolean isCompressed() {
        return compressed;
    }

    public boolean hasPrivate() {
        return priv != null;
    }

    public byte[] getPublicKeyHash() {
        return pubKeyHash;
    }

    public byte[] getPublic() {
        return pub;
    }

    public String getPublicHex() {
        return ByteUtil.toHex(getPublic());
    }

    @Override
    public boolean equals(Object obj) {

        if (obj instanceof ECKey) {
            return Arrays.areEqual(((ECKey) obj).getPrivate(), this.getPrivate())
                    && Arrays.areEqual(((ECKey) obj).getPublic(), this.getPublic())
                    && Arrays.areEqual(((ECKey) obj).getPublicKeyHash(), this.getPublicKeyHash())
                    && ((ECKey) obj).isCompressed() == this.isCompressed();

        }
        return false;
    }

    private void setPub(boolean compressed, boolean fromPrivate, byte[] bytes) {
        this.compressed = compressed;
        if (fromPrivate == true) {
            pub = curve.getG().multiply(priv).getEncoded(compressed);
        } else {
            pub = bytes;
        }
        pubKeyHash = new Hash(pub).keyHash();
    }

    private byte[] getWIFBytes() throws Exception {
        if (hasPrivate() == true) {
            byte[] k = getPrivate();
            if (isCompressed() == true) {
                byte[] encoded = new byte[k.length + 6];
                byte[] ek = new byte[k.length + 2];
                ek[0] = (byte) 0x80;
                System.arraycopy(k, 0, ek, 1, k.length);
                ek[k.length + 1] = 0x01;
                byte[] hash = Hash.hash(ek);
                System.arraycopy(ek, 0, encoded, 0, ek.length);
                System.arraycopy(hash, 0, encoded, ek.length, 4);
                return encoded;
            } else {
                byte[] encoded = new byte[k.length + 5];
                byte[] ek = new byte[k.length + 1];
                ek[0] = (byte) 0x80;
                System.arraycopy(k, 0, ek, 1, k.length);
                byte[] hash = Hash.hash(ek);
                System.arraycopy(ek, 0, encoded, 0, ek.length);
                System.arraycopy(hash, 0, encoded, ek.length, 4);
                return encoded;
            }
        } else {
            throw new Exception("Won't provide WIF if no private key is present");
        }
    }

    public static class ECKeyParser {

        public static ECKey parse(String wif) throws Exception {
            return parseBytes(ByteUtil.fromBase58(wif));
        }

        public static ECKey parseBytes(byte[] keyBytes) throws Exception
        {
            checkChecksum(keyBytes);
            //decode uncompressed
            if (keyBytes.length == 37)
            {
                byte[] key = new byte[keyBytes.length - 5];
                System.arraycopy(keyBytes, 1, key, 0, keyBytes.length - 5);
                return new ECKey(key, false);
            }
            //decode compressed
            else if (keyBytes.length == 38)
            {
                byte[] key = new byte[keyBytes.length - 6];
                System.arraycopy(keyBytes, 1, key, 0, keyBytes.length - 6);
                return new ECKey(key, true);
            }
            throw new Exception("Invalid key length");
        }

        private static void checkChecksum(byte[] keyBytes)throws Exception
        {
            byte[] checksum = new byte[4];
            //last 4 bytes of key are checksum, copy it to checksum byte[]
            System.arraycopy(keyBytes, keyBytes.length - 4, checksum, 0, 4);
            byte[] eckey = new byte[keyBytes.length - 4];
            //anything else is the EC key base, copy it to eckey
            System.arraycopy(keyBytes, 0, eckey, 0, keyBytes.length - 4);
            //now hash the eckey
            byte[] hash = Hash.hash(eckey);
            for (int i = 0; i < 4; i++)
            {
                //compare first 4 bytes of the key hash with corresponding positions in checksum bytes
                if (hash[i] != checksum[i])
                {
                    throw new Exception("checksum mismatch");
                }
            }
        }
    }
}
