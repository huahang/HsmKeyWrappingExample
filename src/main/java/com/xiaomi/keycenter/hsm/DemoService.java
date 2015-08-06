package com.xiaomi.keycenter.hsm;

import org.bouncycastle.operator.OperatorCreationException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.cert.Certificate;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.List;

/**
 * @author huahang
 */
public interface DemoService {
    Key getRootKey(String alias) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException;

    Certificate getRootCertificate(String alias) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException;

    SecretKey generateRootKey(String alias) throws NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException;

    SecretKey generateRootKek(String alias) throws NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException;

    List<String> listRootKeys() throws KeyStoreException;

    byte[] encrypt(String alias, byte[] raw) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException;

    byte[] decrypt(String alias, byte[] cipher) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException;

    byte[] wrap(String alias, Key key) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException;

    Key unwrap(String alias, byte[] cipher, String algorithm, int type) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException;
}
