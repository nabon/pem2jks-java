import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class PemData {
    private final byte[] keyData;
    private final List<byte[]> certDataList;
    private Format format;

    private enum Format {
        PKCS1("-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"),
        PKCS8("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"),
        RFC5915("-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----"),
        RFC7468_CERT("-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"),
        X509("-----BEGIN X509 CERTIFICATE-----", "-----END X509 CERTIFICATE-----");

        private final String begin;
        private final String end;

        Format(String begin, String end){
            this.begin = begin;
            this.end = end;
        }
    }

    public PemData(String filePath) {
        List<String> originalLines = null;
        try {
            originalLines = Files.readAllLines(Paths.get(filePath), StandardCharsets.US_ASCII);
        } catch (IOException e) {
            e.printStackTrace();
        }

        List<String> parsedLines = new ArrayList<>();
        StringBuilder sb = new StringBuilder();

        for(String line: originalLines){
            Format f = checkBeginString(line);
            if(f!=null) {
                format = f;
                sb.append(line.replace(f.begin, "").trim());
            } else if((f=checkEndString(line))!=null) {
                sb.append(line.replace(f.end, "").trim());
                parsedLines.add(sb.toString().trim());
                sb = new StringBuilder();
            } else {
                sb.append(line.trim());
            }
        }

        if (format == Format.RFC7468_CERT || format == Format.X509) {
            keyData = null;
            certDataList = new ArrayList<byte[]>();
            for (String line : parsedLines) {
                certDataList.add(Base64.getDecoder().decode(line));
            }
        } else {
            certDataList = null;
            keyData = Base64.getDecoder().decode(parsedLines.get(0));
        }
    }

    private Format checkBeginString(String str){
        for(Format format: Format.values()){
            if(str.contains(format.begin)){
                return format;
            }
        }
        return null;
    }

    private Format checkEndString(String str){
        for(Format format: Format.values()){
            if(str.contains(format.end)){
                return format;
            }
        }
        return null;
    }

    public List<Certificate> getCertificates() {
        CertificateFactory certFactory;
        List<Certificate> certs = null;
        try {
            certFactory = CertificateFactory.getInstance("X.509");
            certs = new ArrayList<Certificate>();
            for(byte[] certData : certDataList) { 
                certs.add(certFactory.generateCertificate(new ByteArrayInputStream(certData)));
            }
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return certs;
    }

    public PrivateKey getPrivateKey() {
        KeySpec keySpec = null;
        RuntimeException exception = new RuntimeException("Could not obtain Private Key.");

        switch (format) {
            case PKCS1: {
                keySpec = parsePkcs1(keyData);
                break;
            }
            case PKCS8: {
                keySpec = new PKCS8EncodedKeySpec(keyData);
                break;
            }
            default:
                throw exception;
        }

        String[] algorithms = new String[]{"RSA", "DSA", "EC"};
        for(String alg : algorithms){
            try {
                return KeyFactory.getInstance(alg).generatePrivate(keySpec);
            } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                exception.addSuppressed(e);
            }
        }
        throw exception;
    }

    private KeySpec parsePkcs1(byte[] keyData) {
        int pkcs1Length = keyData.length;
        int pkcs8Length = pkcs1Length + 22; // pkcs8Length is used as SEQUENCE length and it does not include the first 4 bytes.
        byte[] pkcs8Header = new byte[] {
            0x30,    // "SEQUENCE"
            (byte) 0x82,    // "The following two bytes indicate the length of this field"
            (byte) ((pkcs8Length >> 8) & 0xff), // Extract upper byte of the total length
            (byte) (pkcs8Length & 0xff), // Extract lower byte of the total length
            0x2,    // "INTEGER" for version
            0x1,    // length: 1 byte
            0x0,    // value: 0
            0x30,   // "SEQUENCE" for privateKeyAlgorithm ID
            0xD,    // length: 13 bytes
            0x6,    // "OBJECT IDENTIFIER"
            0x9,    // length: 9 bytes
            0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0xD, 0x1, 0x1, 0x1,  // value: 1.2.840.113549.1.1.1 - RSA encryption
            0x5, 0x0, // "NULL" with length field 0x00
            0x4,    // "OCTET STRING" for PKCS#1 data
            (byte) 0x82,    // "The following two bytes indicate the length of this field"
            (byte) ((pkcs1Length >> 8) & 0xff), // Extract upper byte
            (byte) (pkcs1Length & 0xff) // Extract lower byte
        };
        byte[] pkcs8bytes = ByteBuffer.allocate(pkcs8Header.length + keyData.length).put(pkcs8Header).put(keyData).array();
        return new PKCS8EncodedKeySpec(pkcs8bytes);
    }
}
