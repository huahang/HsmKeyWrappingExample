package com.xiaomi.keycenter.hsm;

import com.google.inject.Singleton;
import com.safenetinc.luna.LunaAPI;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.LunaTokenObject;
import com.safenetinc.luna.provider.key.LunaSecretKey;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.ECPublicKeySpec;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Properties;
import java.util.Random;
import java.util.concurrent.TimeUnit;

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
    public SecretKey generateRootKey(String alias) throws NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException {
        KeyGenerator kg = KeyGenerator.getInstance("AES", "LunaProvider");
        kg.init(256);
        LunaSecretKey key = (LunaSecretKey) kg.generateKey();
        LunaTokenObject obj = LunaTokenObject.LocateObjectByHandle(key.GetKeyHandle());
        obj.SetBooleanAttribute(LunaAPI.CKA_ENCRYPT, true);
        obj.SetBooleanAttribute(LunaAPI.CKA_DECRYPT, true);
        obj.SetBooleanAttribute(LunaAPI.CKA_WRAP, false);
        obj.SetBooleanAttribute(LunaAPI.CKA_UNWRAP, false);
        obj.SetBooleanAttribute(LunaAPI.CKA_EXTRACTABLE, false);
        if (StringUtils.isNotBlank(alias)) {
            keyStore.setKeyEntry(alias, key, null, null);
        }
        return key;
    }

    @Override
    public SecretKey generateRootKek(String alias) throws NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException {
        KeyGenerator kg = KeyGenerator.getInstance("AES", "LunaProvider");
        kg.init(256);
        LunaSecretKey key = (LunaSecretKey) kg.generateKey();
        LunaTokenObject obj = LunaTokenObject.LocateObjectByHandle(key.GetKeyHandle());
        obj.SetBooleanAttribute(LunaAPI.CKA_ENCRYPT, true);
        obj.SetBooleanAttribute(LunaAPI.CKA_DECRYPT, true);
        obj.SetBooleanAttribute(LunaAPI.CKA_WRAP, true);
        obj.SetBooleanAttribute(LunaAPI.CKA_UNWRAP, true);
        obj.SetBooleanAttribute(LunaAPI.CKA_EXTRACTABLE, false);
        if (StringUtils.isNotBlank(alias)) {
            keyStore.setKeyEntry(alias, key, null, null);
        }
        return key;
    }

    @Override
    public Key getRootKey(String alias) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        Key key = keyStore.getKey(alias, null);
        return key;
    }

    @Override
    public Certificate getRootCertificate(String alias) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        return keyStore.getCertificate(alias);
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

    @Override
    public byte[] wrap(String alias, Key key) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException {
        Key kek = keyStore.getKey(alias, null);
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "LunaProvider");
        aesCipher.init(Cipher.WRAP_MODE, kek, new IvParameterSpec("0102030405060708".getBytes()));
        return aesCipher.wrap(key);
    }

    @Override
    public Key unwrap(String alias, byte[] cipher, String algorithm, int type) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException {
        Key kek = keyStore.getKey(alias, null);
        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "LunaProvider");
        aesCipher.init(Cipher.UNWRAP_MODE, kek, new IvParameterSpec("0102030405060708".getBytes()));
        return aesCipher.unwrap(cipher, algorithm, type);
    }
}
