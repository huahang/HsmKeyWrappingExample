package com.xiaomi.keycenter.hsm;

import com.google.common.collect.Lists;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.provider.key.LunaSecretKey;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

/**
 * @author huahang
 */
public class HsmDemoService implements DemoService {
    private LunaSlotManager slotManager;
    private KeyStore keyStore;
    private String partitionName;
    private String partitionPass;

    HsmDemoService() {
        try {
            Security.addProvider(new com.safenetinc.luna.provider.LunaProvider());
            slotManager = LunaSlotManager.getInstance();
            Properties prop = new Properties();
            File propFile = new File(System.getProperty("user.home"), "partition.properties");
            InputStream in = new FileInputStream(propFile);
            prop.load(in);
            in.close();
            partitionName = prop.getProperty("partitionName");
            partitionPass = prop.getProperty("partitionPass");
            if (partitionName == null || partitionPass == null) {
                System.err.println("Aborting, mandatory properties not set");
                System.exit(-1);
            }
            slotManager.login(partitionName, partitionPass);
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
        return Collections.list(keyStore.aliases());
    }
}
