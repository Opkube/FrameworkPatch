package com.android.internal.util.framework;

import android.app.Application;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyProperties;
import android.util.Log;

import org.lsposed.lsparanoid.Obfuscate;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.StringReader;
import java.lang.reflect.Field;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

@Obfuscate
public final class Android {
    private static final String TAG = "chiteroman";
    private static final PEMKeyPair EC, RSA;
    private static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17");
    private static final List<Certificate> EC_CERTS = new ArrayList<>();
    private static final List<Certificate> RSA_CERTS = new ArrayList<>();
    private static final Map<String, String> map = new HashMap<>();

    static {
        map.put("MANUFACTURER", "Google");
        map.put("MODEL", "Pixel");
        map.put("FINGERPRINT", "google/sailfish/sailfish:8.1.0/OPM1.171019.011/4448085:user/release-keys");
        map.put("BRAND", "google");
        map.put("PRODUCT", "sailfish");
        map.put("DEVICE", "sailfish");
        map.put("RELEASE", "8.1.0");
        map.put("ID", "OPM1.171019.011");
        map.put("INCREMENTAL", "4448085");
        map.put("TYPE", "user");
        map.put("TAGS", "release-keys");
        map.put("SECURITY_PATCH", "2017-12-05");
        try {
            EC = parseKeyPair(Keybox.EC.PRIVATE_KEY);
            EC_CERTS.add(parseCert(Keybox.EC.CERTIFICATE_1));
            EC_CERTS.add(parseCert(Keybox.EC.CERTIFICATE_2));

            RSA = parseKeyPair(Keybox.RSA.PRIVATE_KEY);
            RSA_CERTS.add(parseCert(Keybox.RSA.CERTIFICATE_1));
            RSA_CERTS.add(parseCert(Keybox.RSA.CERTIFICATE_2));
        } catch (Throwable t) {
            Log.e(TAG, t.toString());
            throw new RuntimeException(t);
        }
    }

    private static PEMKeyPair parseKeyPair(String key) throws Throwable {
        try (PEMParser parser = new PEMParser(new StringReader(key))) {
            return (PEMKeyPair) parser.readObject();
        }
    }

    private static Certificate parseCert(String cert) throws Throwable {
        PemObject pemObject;
        try (PemReader reader = new PemReader(new StringReader(cert))) {
            pemObject = reader.readPemObject();
        }
        return new JcaX509CertificateConverter().getCertificate(new X509CertificateHolder(pemObject.getContent()));
    }

    private static Field getField(String fieldName) {
        Field field = null;
        try {
            field = Build.class.getDeclaredField(fieldName);
        } catch (Throwable ignored) {
            try {
                field = Build.VERSION.class.getDeclaredField(fieldName);
            } catch (Throwable t) {
                Log.e(TAG, "Couldn't find field " + fieldName);
            }
        }
        return field;
    }

    public static boolean hasSystemFeature(boolean ret, String name) {
        if (PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY.equals(name)) {
            return false;
        }
        if (PackageManager.FEATURE_STRONGBOX_KEYSTORE.equals(name)) {
            return false;
        }
        return ret;
    }

    public static void newApplication(Context context) {
        if (context == null) return;

        String packageName = context.getPackageName();
        String processName = Application.getProcessName();

        if (packageName == null || processName == null) return;

        if (!"com.google.android.gms".equals(packageName)) return;

        if (!"com.google.android.gms.unstable".equals(processName)) return;

        LOG("DroidGuard detected!");
        map.forEach((fieldName, value) -> {
            setField(fieldName, value);
        });
    }

    public static Certificate[] engineGetCertificateChain(Certificate[] caList) {
        if (caList == null) return null;
        if (caList.length < 2) return caList;
        try {
            X509CertificateHolder holder = new X509CertificateHolder(caList[0].getEncoded());

            X509Certificate leaf = new JcaX509CertificateConverter().getCertificate(holder);

            Extension ext = holder.getExtension(OID);

            if (ext == null) return caList;

            ASN1Sequence sequence = ASN1Sequence.getInstance(ext.getExtnValue().getOctets());

            ASN1Encodable[] encodables = sequence.toArray();

            ASN1Sequence teeEnforced = (ASN1Sequence) encodables[7];

            ASN1EncodableVector vector = new ASN1EncodableVector();

            for (ASN1Encodable asn1Encodable : teeEnforced) {
                ASN1TaggedObject taggedObject = (ASN1TaggedObject) asn1Encodable;
                if (taggedObject.getTagNo() == 704) continue;
                vector.add(taggedObject);
            }

            LinkedList<Certificate> certificates;

            X509v3CertificateBuilder builder;
            ContentSigner signer;

            if (KeyProperties.KEY_ALGORITHM_EC.equals(leaf.getPublicKey().getAlgorithm())) {
                certificates = new LinkedList<>(EC_CERTS);
                builder = new X509v3CertificateBuilder(new X509CertificateHolder(EC_CERTS.get(0).getEncoded()).getSubject(), holder.getSerialNumber(), holder.getNotBefore(), holder.getNotAfter(), holder.getSubject(), EC.getPublicKeyInfo());
                signer = new JcaContentSignerBuilder(leaf.getSigAlgName()).build(new JcaPEMKeyConverter().getPrivateKey(EC.getPrivateKeyInfo()));
            } else {
                certificates = new LinkedList<>(RSA_CERTS);
                builder = new X509v3CertificateBuilder(new X509CertificateHolder(RSA_CERTS.get(0).getEncoded()).getSubject(), holder.getSerialNumber(), holder.getNotBefore(), holder.getNotAfter(), holder.getSubject(), RSA.getPublicKeyInfo());
                signer = new JcaContentSignerBuilder(leaf.getSigAlgName()).build(new JcaPEMKeyConverter().getPrivateKey(RSA.getPrivateKeyInfo()));
            }

            byte[] verifiedBootKey = new byte[32];
            byte[] verifiedBootHash = new byte[32];

            ThreadLocalRandom.current().nextBytes(verifiedBootKey);
            ThreadLocalRandom.current().nextBytes(verifiedBootHash);

            ASN1Encodable[] rootOfTrustEnc = {new DEROctetString(verifiedBootKey), ASN1Boolean.TRUE, new ASN1Enumerated(0), new DEROctetString(verifiedBootHash)};

            ASN1Sequence rootOfTrustSeq = new DERSequence(rootOfTrustEnc);

            ASN1TaggedObject rootOfTrustTagObj = new DERTaggedObject(704, rootOfTrustSeq);

            vector.add(rootOfTrustTagObj);

            ASN1Sequence hackEnforced = new DERSequence(vector);

            encodables[7] = hackEnforced;

            ASN1Sequence hackedSeq = new DERSequence(encodables);

            ASN1OctetString hackedSeqOctets = new DEROctetString(hackedSeq);

            Extension hackedExt = new Extension(OID, false, hackedSeqOctets);

            builder.addExtension(hackedExt);

            for (ASN1ObjectIdentifier extensionOID : holder.getExtensions().getExtensionOIDs()) {
                if (OID.getId().equals(extensionOID.getId())) continue;
                builder.addExtension(holder.getExtension(extensionOID));
            }

            certificates.addFirst(new JcaX509CertificateConverter().getCertificate(builder.build(signer)));

            return certificates.toArray(new Certificate[0]);

        } catch (Throwable t) {
            Log.e(TAG, t.toString());
        }
        return caList;
    }

    private static boolean classContainsField(Class className, String fieldName) {
        for (Field field : className.getDeclaredFields()) {
            if (field.getName().equals(fieldName)) return true;
        }
        return false;
    }

    private static void setField(String name, String value) {
        if (value.isEmpty()) {
            LOG(String.format("%s is empty, skipping", name));
            return;
        }

        Field field = null;
        String oldValue = null;
        Object newValue = null;

        try {
            if (classContainsField(Build.class, name)) {
                field = Build.class.getDeclaredField(name);
            } else if (classContainsField(Build.VERSION.class, name)) {
                field = Build.VERSION.class.getDeclaredField(name);
            } else {
                LOG(String.format("Couldn't determine '%s' class name", name));
                return;
            }
        } catch (NoSuchFieldException e) {
            LOG(String.format("Couldn't find '%s' field name: " + e, name));
            return;
        }
        field.setAccessible(true);
        try {
            oldValue = String.valueOf(field.get(null));
        } catch (IllegalAccessException e) {
            LOG(String.format("Couldn't access '%s' field value: " + e, name));
            return;
        }
        if (value.equals(oldValue)) {
            LOG(String.format("[%s]: %s (unchanged)", name, value));
            return;
        }
        Class<?> fieldType = field.getType();
        if (fieldType == String.class) {
            newValue = value;
        } else if (fieldType == int.class) {
            newValue = Integer.parseInt(value);
        } else if (fieldType == long.class) {
            newValue = Long.parseLong(value);
        } else if (fieldType == boolean.class) {
            newValue = Boolean.parseBoolean(value);
        } else {
            LOG(String.format("Couldn't convert '%s' to '%s' type", value, fieldType));
            return;
        }
        try {
            field.set(null, newValue);
        } catch (IllegalAccessException e) {
            LOG(String.format("Couldn't modify '%s' field value: " + e, name));
            return;
        }
        field.setAccessible(false);
        LOG(String.format("[%s]: %s -> %s", name, oldValue, value));
    }

    private static String logParseField(Field field) {
        Object value = null;
        String type = field.getType().getName();
        String name = field.getName();
        try {
            value = field.get(null);
        } catch (IllegalAccessException|NullPointerException e) {
            return String.format("Couldn't access '%s' field value: " + e, name);
        }
        return String.format("<%s> %s: %s", type, name, String.valueOf(value));
    }

    private static void logFields() {
        for (Field field : Build.class.getDeclaredFields()) {
            LOG("Build " + logParseField(field));
        }
        for (Field field : Build.VERSION.class.getDeclaredFields()) {
            LOG("Build.VERSION " + logParseField(field));
        }
    }

    static void LOG(String msg) {
        Log.d("PIF/Java", msg);
    }
}