package com.xiaomi.keycenter.hsm;

import com.google.inject.Singleton;
import com.safenetinc.luna.LunaSlotManager;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.ECPublicKeySpec;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

/**
 * @author huahang
 */
@Singleton
public class HsmDemoService implements DemoService {
    private KeyStore keyStore;

    HsmDemoService() {
        try {
            Security.addProvider(new com.safenetinc.luna.provider.LunaProvider());
            Security.addProvider(new BouncyCastleProvider());
            LunaSlotManager slotManager = LunaSlotManager.getInstance();
            Properties prop = new Properties();
            File propFile = new File(System.getProperty("user.home"), "partition.properties");
            InputStream in = new FileInputStream(propFile);
            prop.load(in);
            in.close();
            String partitionName = prop.getProperty("partitionName");
            String partitionPass = prop.getProperty("partitionPass");
            if (partitionName == null || partitionPass == null) {
                System.err.println("Aborting, mandatory properties not set");
                System.exit(-1);
            }
            slotManager.login(partitionName, partitionPass);
            slotManager.setSecretKeysExtractable(true);
            keyStore = KeyStore.getInstance("Luna");
            keyStore.load(null, null);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        } finally {
        }
    }

    @Override
    public KeyPair generateRootKeyPair(String alias) throws NoSuchProviderException, NoSuchAlgorithmException, CertificateException, KeyStoreException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA", "LunaProvider");
        g.initialize(1024);
        KeyPair keyPair = g.generateKeyPair();
        // http://www.bouncycastle.org/wiki/display/JA1/X.509+Public+Key+Certificate+and+Certification+Request+Generation
        //X509v3CertificateBuilder builder = new X509v3CertificateBuilder();
        //keyStore.setKeyEntry(alias, keyPair.getPrivate(), null, ArrayUtils.addAll(null, cert));
        keyStore.setKeyEntry(alias, keyPair.getPrivate(), null, null);
        return keyPair;
    }

    @Override
    public SecretKey generateRootKey(String alias) throws NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException {
        KeyGenerator kg = KeyGenerator.getInstance("AES", "LunaProvider");
        kg.init(256);
        SecretKey key = kg.generateKey();
        keyStore.setKeyEntry(alias, key, null, null);
        return key;
    }

    @Override
    public List<String> listRootKeys() throws KeyStoreException {
        List<String> aliasList = Collections.list(keyStore.aliases());
        Collections.sort(aliasList);
        return aliasList;
    }

    @Override
    public byte[] encrypt(String alias, byte[] raw) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Key key = keyStore.getKey(alias, null);
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding", "LunaProvider");
        aesCipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec("0102030405060708".getBytes()));
        return aesCipher.doFinal(raw);
    }

    @Override
    public byte[] decrypt(String alias, byte[] cipher) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Key key = keyStore.getKey(alias, null);
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding", "LunaProvider");
        aesCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec("0102030405060708".getBytes()));
        return aesCipher.doFinal(cipher);
    }
}
