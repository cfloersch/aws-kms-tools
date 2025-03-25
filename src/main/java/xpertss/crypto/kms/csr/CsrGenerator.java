package xpertss.crypto.kms.csr;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import xpertss.crypto.kms.provider.signature.KmsSigningAlgorithm;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

public class CsrGenerator {

    /**
     * Generate CSR.
     *
     * @param keyPair
     * @param csrInfo
     * @param kmsSigningAlgorithm
     * @return
     */
    public static String generate(KeyPair keyPair, CsrInfo csrInfo, KmsSigningAlgorithm kmsSigningAlgorithm)
    {
        try {
            X500Principal subject = new X500Principal(csrInfo.toString());

            ContentSigner signGen = new JcaContentSignerBuilder(kmsSigningAlgorithm.getAlgorithm()).setProvider("KMS").build(keyPair.getPrivate());
            ExtensionsGenerator extGen = createExtensions();

            PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
            PKCS10CertificationRequest csr = builder.build(signGen);

            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            JcaPEMWriter pemWriter = new JcaPEMWriter(new OutputStreamWriter(byteArrayOutputStream));
            pemWriter.writeObject(csr);
            pemWriter.close();

            return byteArrayOutputStream.toString(StandardCharsets.UTF_8.toString());

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    private static ExtensionsGenerator createExtensions()
        throws IOException
    {
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));

            /*
              GeneralNames subjectAlternativeNames = new GeneralNames(new GeneralName(GeneralName.dNSName, ""));
              extGen.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
             */

        KeyPurposeId[] keyPurposeIds = new KeyPurposeId[] {
                KeyPurposeId.id_kp_codeSigning
        };
        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(keyPurposeIds);
        extGen.addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage);
        return extGen;
    }

}
