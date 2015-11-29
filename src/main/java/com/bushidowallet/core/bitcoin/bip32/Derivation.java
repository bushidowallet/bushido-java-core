package com.bushidowallet.core.bitcoin.bip32;

/**
 * Created by Jesion on 2015-01-19.
 */
public class Derivation {

    private ExtendedKey root;

    public Derivation(ExtendedKey root) {
        this.root = root;
    }

    public ExtendedKey derive(String path) throws Exception {
        String[] p = path.split("/");
        if (p.length == 2) {
            int sequence = Integer.parseInt(p[1]);
            return basic(sequence);
        } else if (p.length == 3) {
            int accountType = Integer.parseInt(p[2]);
            int account = Integer.parseInt(p[1]);
            return accountMaster(accountType, account);
        } else if (p.length == 4) {
            int accountType = Integer.parseInt(p[2]);
            int account = Integer.parseInt(p[1]);
            int key = Integer.parseInt(p[3]);
            return accountKey(accountType, account, key);
        }
        throw new Exception("Invalid derivation path");
    }

    /**
     * Level 1
     *
     * Path m/i
     *
     * @param sequence
     * @return
     * @throws Exception
     */
    public ExtendedKey basic(int sequence) throws Exception {
        return root.derive(sequence);
    }

    /**
     * Account Master
     *
     * Path m/k/0 or m/k/1
     *
     * @param account
     * @param type
     * @return
     * @throws Exception
     */
    public ExtendedKey accountMaster(int type, int account) throws Exception {
        if (type == 0) {
            return externalAccountMaster(account);
        } else if (type == 1) {
            return internalAccountMaster(account);
        }
        throw new Exception("Account type not recognized");
    }

    /**
     * External Account Master
     *
     * Path m/k/0
     *
     * @param account
     * @return
     * @throws Exception
     */
    public ExtendedKey externalAccountMaster(int account) throws Exception {
        ExtendedKey base = root.derive(account);
        return base.derive(0);
    }

    /**
     * Internal Account Master
     *
     * Path m/k/1
     *
     * @param account
     * @return
     * @throws Exception
     */
    public ExtendedKey internalAccountMaster(int account) throws Exception {
        ExtendedKey base = root.derive(account);
        return base.derive(1);
    }

    /**
     * Account Key
     *
     * Path m/k/0/i or m/k/1/i
     *
     * @param accountType
     * @param account
     * @param key
     * @return
     * @throws Exception
     */
    public ExtendedKey accountKey(int accountType, int account, int key) throws Exception {
        ExtendedKey base = accountMaster(accountType, account);
        return base.derive(key);
    }
}
