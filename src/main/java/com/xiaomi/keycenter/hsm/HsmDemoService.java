package com.xiaomi.keycenter.hsm;

import com.google.inject.Singleton;
import com.safenetinc.luna.LunaSlotManager;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
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
    public byte[] encrypt(String alias, byte[] raw) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Key key = keyStore.getKey(alias, null);
        Cipher aesCipher = Cipher.getInstance("AES/ECB/NoPadding", "LunaProvider");
        aesCipher.init(Cipher.ENCRYPT_MODE, key);
        return aesCipher.doFinal(raw);
    }

    @Override
    public byte[] decrypt(String alias, byte[] cipher) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Key key = keyStore.getKey(alias, null);
        Cipher aesCipher = Cipher.getInstance("AES/ECB/NoPadding", "LunaProvider");
        aesCipher.init(Cipher.DECRYPT_MODE, key);
        return aesCipher.doFinal(cipher);
    }


}
