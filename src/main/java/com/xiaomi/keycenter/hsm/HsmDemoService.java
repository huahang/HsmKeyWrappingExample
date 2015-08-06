package com.xiaomi.keycenter.hsm;

import com.google.inject.Singleton;
import com.safenetinc.luna.LunaSlotManager;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
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
    public KeyPair generateRootKeyPair(String alias) throws NoSuchProviderException, NoSuchAlgorithmException, CertificateException, KeyStoreException, OperatorCreationException, IOException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA", "LunaProvider");
        g.initialize(2048);
        KeyPair keyPair = g.generateKeyPair();
        Date startDate = new Date(System.currentTimeMillis());
        Date expiryDate = new Date(startDate.getTime() + TimeUnit.DAYS.toMillis(356 * 30));
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        serialNumber.shiftLeft(64);
        serialNumber.add(BigInteger.valueOf(Math.abs(new SecureRandom().nextLong())));
        X500Name x500Name = X500Name.getInstance(new X500Principal("CN=My Root Certificate").getEncoded());
        X509v1CertificateBuilder certBuilder = new X509v1CertificateBuilder(
                x500Name, serialNumber, startDate, expiryDate, x500Name,
                SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded())
        );
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
        BcContentSignerBuilder contentSignerBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);
        ContentSigner contentSigner = contentSignerBuilder.build(new AsymmetricKeyParameter(false));
        X509CertificateHolder certificateHolder = certBuilder.build(contentSigner);
        Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(
                new ByteArrayInputStream(certificateHolder.getEncoded())
        );
        keyStore.setKeyEntry(alias, keyPair.getPrivate(), null, ArrayUtils.addAll(null, certificate));
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
