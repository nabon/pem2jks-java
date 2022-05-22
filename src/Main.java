import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

public class Main {
    private final int passwordLength = 20;
    private final String chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    private final Random random = new Random();

    private final String trustStoreFileNamePrefix = "truststore";
    private final String rootcaEntryAliasPrefix = "rootca-cert-";
    private final String keyStoreFileNamePrefix = "keystore";
    private final String clientKeyEntryAliasPrefix = "client-key";

    private String genRandomChars() {
        StringBuilder sb = new StringBuilder();
        for(int i=0;i<passwordLength;i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return new String(sb);
    }

    // Each certificate in certFilePaths must be a self-signed certificate (i.e., root CA certificate).
    private void getTrustStore(String[] certFilePaths) {
        try {
            List<Certificate> certs = new ArrayList<Certificate>();
            for(String path : certFilePaths){
                certs.addAll(new PemData(path).getCertificates());
            }

            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(null, null);
            for(int i=0;i<certs.size();i++){
                trustStore.setCertificateEntry(rootcaEntryAliasPrefix+i, certs.get(i));
            }
            
            char[] pass = genRandomChars().toCharArray(); 
            File temp = File.createTempFile(trustStoreFileNamePrefix, ".jks");
//            temp.deleteOnExit();
            trustStore.store(new FileOutputStream(temp), pass);
            
            System.out.println(temp.getAbsolutePath());
            System.out.println(pass);
        } catch (Exception e) {
            throw new RuntimeException("Cannot build keystore", e);
        }
    }

    // Certificate in certFilePaths must be in the order of client and intermediate-CA. Root CA certificate is not necessarily.
    public void getKeyStore(String[] certFilePaths, String keyFilePath) {
        try {
            PrivateKey key = new PemData(keyFilePath).getPrivateKey();
            Certificate[] certArray = new Certificate[certFilePaths.length];
            for(int i=0;i<certFilePaths.length;i++){
                certArray[i] = new PemData(certFilePaths[i]).getCertificates().get(0);
            }

            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, null);

            char[] pass = genRandomChars().toCharArray(); 
            File temp = File.createTempFile(keyStoreFileNamePrefix, ".jks");
//            temp.deleteOnExit();
            keyStore.setKeyEntry(clientKeyEntryAliasPrefix, key, pass, certArray);
            keyStore.store(new FileOutputStream(temp), pass);

            System.out.println(temp.getAbsolutePath());
            System.out.println(pass);
        } catch (Exception e) {
            throw new RuntimeException("Cannot build keystore", e);
        }
    }

    public static void main(String[] args) throws Exception {
        Main main = new Main();
        main.getTrustStore(new String[]{"rootca.crt"});
        main.getKeyStore(new String[]{"client.crt","ica.crt"}, "client.key");
    }
}
