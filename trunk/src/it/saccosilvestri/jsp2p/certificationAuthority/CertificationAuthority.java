package it.saccosilvestri.jsp2p.certificationAuthority;

import it.saccosilvestri.jsp2p.utility.CertificateVerificationUtility;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;

public class CertificationAuthority {

	private KeyPair pair;
	X509Certificate caCert;

	private X509Certificate selfCertificate(KeyPair pair)
			throws InvalidKeyException, NoSuchProviderException,
			SignatureException, NoSuchAlgorithmException,
			CertificateEncodingException, IllegalStateException {

		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		certGen.setIssuerDN(new X509Name("CN=Pippo"));
		certGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
		certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
		certGen.setSubjectDN(new X509Name("CN=Pippo"));
		certGen.setPublicKey(pair.getPublic());
		certGen.setSignatureAlgorithm("SHA1WithRSAEncryption");

		return certGen.generate(pair.getPrivate());
	}

	public KeyPair generateCertificate(int i)
			throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException,
			NoSuchProviderException, SignatureException, CertificateException, IOException {
		String filename = ("certificate_for_peer_" + i + ".crt");
		X509Name subjectName = new X509Name("CN=Peer" + i);
		Date startDate = new Date(System.currentTimeMillis()); // time from
																// which
																// certificate
																// is valid
		Date expiryDate = new Date(System.currentTimeMillis() + 5000000); // time
																			// after
																			// which
																			// certificate
																			// is
																			// not
																			// valid
		BigInteger serialNumber = BigInteger
				.valueOf(System.currentTimeMillis()); // serial number for
														// certificate
		PrivateKey caKey = pair.getPrivate(); // private key of the certifying
												// authority (ca) certificate
		// Building keys
		System.out.println("Building keys...");
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA","BC");
		keyPairGen.initialize(1024);
		KeyPair keyPair = keyPairGen.generateKeyPair(); // public/private key
														// pair that we are
														// creating certificate
														// for
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

		certGen.setSerialNumber(serialNumber);
		certGen.setIssuerDN((X509Name) caCert.getIssuerDN());
		certGen.setNotBefore(startDate);
		certGen.setNotAfter(expiryDate);
		certGen.setSubjectDN(subjectName);
		certGen.setPublicKey(keyPair.getPublic());
		certGen.setSignatureAlgorithm("SHA1WithRSAEncryption");
		X509Certificate cert = certGen.generate(caKey); // note: private key of
														// CA

		// Controlli
		CertificateVerificationUtility.checkAndExportCertificate(cert,caCert.getPublicKey(),filename);
		
		return keyPair;
		
	}


	public CertificationAuthority() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, IllegalStateException, CertificateException, IOException  {

			String filename = "./ca_certificate.crt";

			// Keys
			System.out.println("Building keys...");
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA","BC");
			keyPairGen.initialize(1024);
			pair = keyPairGen.generateKeyPair();

			// SelfCertificate
			System.out.println("Building certificate...");
			caCert = selfCertificate(pair);

			// Controlli
			CertificateVerificationUtility.checkAndExportCertificate(caCert,caCert.getPublicKey(),filename);

	}

}
