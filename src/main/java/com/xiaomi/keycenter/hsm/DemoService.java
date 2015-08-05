package com.xiaomi.keycenter.hsm;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.List;

/**
 * @author huahang
 */
public interface DemoService {
    public static enum Algorithm {
        AES,
        RSA,
        ECC
    }
    SecretKey generateRootKey(String alias) throws NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException;
    List<String> listRootKeys() throws KeyStoreException;
}
