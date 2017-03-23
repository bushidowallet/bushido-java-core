package com.bushidowallet.core.bitcoin;

import com.bushidowallet.core.bitcoin.bip32.Hash;
import com.bushidowallet.core.bitcoin.script.Script;
import com.bushidowallet.core.crypto.util.ByteUtil;

/**
 * Created by Jesion on 2015-03-27.
 */
public class Address {

    public static String PAY_TO_PUBLIC_KEY_HASH = "pubkeyhash";
    public static String PAY_TO_SCRIPT_HASH = "scripthash";

    private String type;
    //either public key hash or script hash, depends on type
    private byte[] hash;
    private int addressFlag;

    /**
     * Constructs an address from Script
     *
     * @param script
     */
    public Address(Script script) throws Exception {

        if (script.isMultiSigOut()) {
            this.type = PAY_TO_SCRIPT_HASH;
            this.addressFlag = 0x5;
            this.hash = new Hash(script.getBytes()).keyHash();
        }
    }

    public Address(byte[] pubKeyHash) {

        this.type = PAY_TO_PUBLIC_KEY_HASH;
        this.hash = pubKeyHash;
        this.addressFlag = 0x0;
    }

    public Address(String address) throws Exception {

        byte[] addressBytes = ByteUtil.fromBase58WithChecksum(address);
        byte[] hash = new byte[addressBytes.length - 1];
        int flag = addressBytes[0];
        if (flag == 0x5) {
            type = PAY_TO_SCRIPT_HASH;
            System.out.println("creating p2sh address instance for " + address);
        } else if (flag == 0x0) {
            type = PAY_TO_PUBLIC_KEY_HASH;
            System.out.println("creating p2pkh address instance for " + address);
        } else if(flag == 0x6F) {
        	// add testnet address support
            type = PAY_TO_PUBLIC_KEY_HASH;
            System.out.println("creating p2pkh testnet address instance for " + address);
        }
        System.arraycopy(addressBytes, 1, hash, 0, addressBytes.length - 1);
        this.hash = hash;
        addressFlag = flag;
    }

    public boolean isPayToScriptHash() {
        return type == PAY_TO_SCRIPT_HASH;
    }

    public boolean isPayToPublicKeyHash() {
        return type == PAY_TO_PUBLIC_KEY_HASH;
    }

    public String toString() {
        byte[] addressBytes = new byte[1 + hash.length + 4];
        addressBytes[0] = (byte) (addressFlag & 0xff);
        System.arraycopy (hash, 0, addressBytes, 1, hash.length);
        byte[] check = Hash.hash(addressBytes, 0, hash.length + 1);
        System.arraycopy(check, 0, addressBytes, hash.length + 1, 4);
        return ByteUtil.toBase58(addressBytes);
    }

    public byte[] getHash() {
        return hash;
    }
}
