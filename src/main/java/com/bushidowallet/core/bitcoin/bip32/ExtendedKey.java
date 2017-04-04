package com.bushidowallet.core.bitcoin.bip32;

import com.bushidowallet.core.bitcoin.Address;
import com.bushidowallet.core.crypto.util.ByteUtil;
import org.bouncycastle.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;

/**
 * Created by Jesion on 2015-01-14.
 *
 * ExtendedKey class represents BIP32 key, which is able to provide derived keys according to the spec.
 * It composes ECKey class which is responsible for providing Elliptic Curve transformations required to support key derivation.
 */
public class ExtendedKey {

    private static final byte[] xpub = new byte[] { 0x04, (byte) 0x88, (byte) 0xB2, (byte) 0x1E };
    private static final byte[] xprv = new byte[] { 0x04, (byte) 0x88, (byte) 0xAD, (byte) 0xE4 };

    private byte[] chainCode;
    private ECKey ecKey;
    private int sequence;
    private int depth;
    private int parentFingerprint;

    /**
     * Constructing master
     *
     * By default, using compressed keys (generating Electrum Wallet compatible keys)
     *
     * @param keyHash
     */
    public ExtendedKey(byte[] keyHash) {
        this(keyHash, true);
    }

    /**
     * Constructing master
     *
     * @param keyHash - Master key hash
     * @param compressed - Indicates if public key is compressed for EC calculations. If true, output will be compatibile with Electrum Wallet, oherwise with Armory (0.92.3)
     */
    public ExtendedKey(byte[] keyHash, boolean compressed) {

        this(keyHash, compressed, 0, 0, 0, null);
    }

    /**
     * Constructing a derived key
     *
     * @param keyHash - Derived key hash
     * @param compressed - Indicates if public key is compressed for EC calculations
     * @param sequence - Derivation sequence
     * @param depth - Derivation depth
     * @param parentFingerprint - Parent key fingerprint
     * @param ecKey - Parent ECKey
     */
    public ExtendedKey(byte[] keyHash, boolean compressed, int sequence, int depth, int parentFingerprint, ECKey ecKey) {

        //key hash left side, private key base
        byte[] l = Arrays.copyOfRange(keyHash, 0, 32);
        //key hash right side, chaincode
        byte[] r = Arrays.copyOfRange(keyHash, 32, 64);
        //r is chainCode bytes
        this.chainCode = r;
        this.sequence = sequence;
        this.depth = depth;
        this.parentFingerprint = parentFingerprint;

        if (ecKey != null) {
            this.ecKey = new ECKey(l, ecKey);
        } else {
            this.ecKey = new ECKey(l, compressed);
        }
    }

    /**
     * Constructing a parsed key
     *
     * @param chainCode
     * @param sequence
     * @param depth
     * @param parentFingerprint
     * @param ecKey
     */
    public ExtendedKey(byte[] chainCode, int sequence, int depth, int parentFingerprint, ECKey ecKey) {
        this.chainCode = chainCode;
        this.sequence = sequence;
        this.depth = depth;
        this.parentFingerprint = parentFingerprint;
        this.ecKey = ecKey;
    }

    public String serializePublic() throws Exception {
        return new ExtendedKeySerializer().serialize(xpub,
                this.depth,
                this.parentFingerprint,
                this.sequence,
                this.chainCode,
                this.ecKey.getPublic()
        );
    }

    public String serializePrivate() throws Exception {
        if (ecKey.hasPrivate()) {
            return new ExtendedKeySerializer().serialize(xprv,
                    this.depth,
                    this.parentFingerprint,
                    this.sequence,
                    this.chainCode,
                    this.ecKey.getPrivate()
            );
        }
        throw new Exception("This is a public key only. Can't serialize a private key");
    }

    public ECKey getECKey() {
        return this.ecKey;
    }

    /**
     * Takes a serialized key (public or private) and constructs an instance of ExtendedKey
     *
     * @param serialized
     * @param compressed
     * @return
     * @throws Exception
     */
    public static ExtendedKey parse(String serialized, boolean compressed) throws Exception {
        return ExtendedKeyParser.parse(serialized, compressed);
    }

    /**
     * Derives a child key from a valid instance of key
     * Currently only supports simple derivation (m/i', where m is master and i is level-1 derivation of master)
     * Key derivation spec is much richer and includes accounts with internal/external key chains as well, due to be implemented
     * @return
     */
    public ExtendedKey derive(int i) throws Exception {

        return getChild(i);
    }

    private ExtendedKey getChild(int i) throws Exception {

        //Hmac hashing algo, which is using parents chainCode as its key
        Mac mac = Mac.getInstance("HmacSHA512", "BC");
        SecretKey key = new SecretKeySpec(chainCode, "HmacSHA512");
        mac.init (key);
        //treating master's pub key as base... not sure why but simple m/i derivation goes by pub only but has to be tested a lot
        byte[] pub = this.ecKey.getPublic();
        byte[] child = new byte[pub.length + 4];
        System.arraycopy(pub, 0, child, 0, pub.length);
        //now some byte shifting
        child[pub.length] = (byte) ((i >>> 24) & 0xff);
        child[pub.length + 1] = (byte) ((i >>> 16) & 0xff);
        child[pub.length + 2] = (byte) ((i >>> 8) & 0xff);
        child[pub.length + 3] = (byte) (i & 0xff);
        byte[] keyHash = mac.doFinal(child);
        return new ExtendedKey(keyHash, this.ecKey.isCompressed(), i, this.depth + 1, getFingerPrint(), this.ecKey);
    }

    /**
     * Gets an Integer representation of master public key hash
     * @return
     */
    public int getFingerPrint()
    {
        int fingerprint = 0;
        for (int i = 0; i < 4; i++) {
            fingerprint <<= 8;
            fingerprint |= this.ecKey.getPublicKeyHash()[i] & 0xff;
        }
        return fingerprint;
    }

    public byte[] getChainCode() {
        return chainCode;
    }

    /**
     * Gets a Wallet Import Format - a Base58 String representation of private key that can be imported to
     * - Electrum Wallet : if we are working with compressed public keys
     * - Armory Wallet : if we are working with uncompressed public keys
     * allowing to sweep funds sent to a corresponding address.
     * There is no easy way to support both, I would rather expect Armory to upgrade and support compressed keys
     * By default we are working with compressed keys, supporting Electrum wallet (see constructor of this class)
     * @return
     * @throws Exception
     */
    public String getWIF() throws Exception {
        return this.ecKey.getWIF();
    }

    /**
     * Gets an Address
     * @return
     */
    public Address getAddress() {
        return new Address(this.ecKey.getPublicKeyHash());
    }

    /**
     * Gets public key bytes
     * @return
     */
    public byte[] getPublic() {
        return this.ecKey.getPublic();
    }

    /**
     * Gets public key hexadecimal string
     * @return
     */
    public String getPublicHex() {
        return ByteUtil.toHex(getPublic());
    }

    @Override
    public boolean equals(Object obj)
    {
        if (obj instanceof ExtendedKey)
        {
            return ecKey.equals(((ExtendedKey) obj).ecKey)
                    && Arrays.areEqual(chainCode, ((ExtendedKey) obj).chainCode)
                    && depth == ((ExtendedKey) obj).depth
                    && parentFingerprint == ((ExtendedKey) obj).parentFingerprint
                    && sequence == ((ExtendedKey) obj).sequence;
        }
        return false;
    }

    private class ExtendedKeySerializer {

        /**
         *
         * @param version
         * @param depth
         * @param parentFingerprint
         * @param sequence - Key derivation sequence
         * @param chainCode
         * @param keyBytes - Actual key bytes coming from the Elliptic Curve
         * @return
         * @throws Exception
         */
        public String serialize(byte[] version,
                                int depth,
                                int parentFingerprint,
                                int sequence,
                                byte[] chainCode,
                                byte[] keyBytes) throws Exception {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(version);
            out.write(depth & 0xff);
            out.write((parentFingerprint >>> 24) & 0xff);
            out.write((parentFingerprint >>> 16) & 0xff);
            out.write((parentFingerprint >>> 8) & 0xff);
            out.write(parentFingerprint & 0xff);
            out.write((sequence >>> 24) & 0xff);
            out.write((sequence >>> 16) & 0xff);
            out.write((sequence >>> 8) & 0xff);
            out.write(sequence & 0xff);
            out.write(chainCode);
            if (version.equals(xprv)) {
                out.write(0x00);
            }
            out.write(keyBytes);
            return ByteUtil.toBase58WithChecksum(out.toByteArray());
        }
    }

    public static class ExtendedKeyParser {

        public static ExtendedKey parse(String serialized, boolean compressed) throws Exception {
            byte[] data = ByteUtil.fromBase58WithChecksum(serialized);
            if (data.length != 78)
            {
                throw new Exception("Invalid extended key");
            }
            byte[] type = Arrays.copyOf(data, 4);
            boolean hasPrivate;
            if (Arrays.areEqual(type, xprv))
            {
                hasPrivate = true;
            }
            else if (Arrays.areEqual(type, xpub))
            {
                hasPrivate = false;
            }
            else
            {
                throw new Exception("Invalid or unsupported key type");
            }
            int depth = data[4] & 0xff;
            int parentFingerprint = data[5] & 0xff;
            parentFingerprint <<= 8;
            parentFingerprint |= data[6] & 0xff;
            parentFingerprint <<= 8;
            parentFingerprint |= data[7] & 0xff;
            parentFingerprint <<= 8;
            parentFingerprint |= data[8] & 0xff;
            int sequence = data[9] & 0xff;
            sequence <<= 8;
            sequence |= data[10] & 0xff;
            sequence <<= 8;
            sequence |= data[11] & 0xff;
            sequence <<= 8;
            sequence |= data[12] & 0xff;
            final byte[] chainCode = Arrays.copyOfRange(data, 13, 13 + 32);
            final byte[] keyBytes = Arrays.copyOfRange(data, 13 + 32, data.length);
            final ECKey ecKey = new ECKey(keyBytes, compressed, hasPrivate);
            return new ExtendedKey(chainCode, sequence, depth, parentFingerprint, ecKey);
        }
    }
}
