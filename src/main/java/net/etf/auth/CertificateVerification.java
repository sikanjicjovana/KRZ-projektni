package net.etf.auth;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jcajce.provider.asymmetric.X509;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;


public class CertificateVerification
{
    static
    {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static  boolean verifyCertificate(String caCertPath, String clientCertPath)
    {
        try{
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");

            X509Certificate caCert = (X509Certificate) certificateFactory.generateCertificate(new FileInputStream(caCertPath));
            X509Certificate clientCert = (X509Certificate) certificateFactory.generateCertificate(new FileInputStream(clientCertPath));

            clientCert.verify(caCert.getPublicKey());

            if(isCertificateRevoked(clientCert, "data/crl/lista1.pem"))
            {
                System.out.println("Sertifikat je opozvan.");
                return false;
            }

            System.out.println("Sertifikat je validan.");
            return true;

        }catch(Exception e)
        {
            System.out.println("Sertifikat nije validan.");
            return false;
        }
    }

    private static boolean isCertificateRevoked(X509Certificate certificate, String crlPath)
    {
        try{
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");
            X509CRL crl = (X509CRL) certificateFactory.generateCRL(new FileInputStream(crlPath));

            if(crl.isRevoked(certificate))
            {
                System.out.println("Sertifikat je opozvan.");
                return true;
            }
        }catch(Exception e)
        {
            System.out.println("Greška pri provjeri CRL liste.");
        }
        return false;
    }

    public static String getCommonName(X509Certificate certificate) throws Exception
    {
        X509CertificateHolder certHolder = new X509CertificateHolder(certificate.getEncoded());
        X500Name x500name = certHolder.getSubject();
        RDN[] rdns = x500name.getRDNs(BCStyle.CN);
        if (rdns != null && rdns.length > 0)
        {
            return rdns[0].getFirst().getValue().toString();
        }
        return null;
    }
}
