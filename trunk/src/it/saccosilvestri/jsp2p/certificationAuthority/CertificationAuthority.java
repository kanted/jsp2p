package it.saccosilvestri.jsp2p.certificationAuthority;

import it.saccosilvestri.jsp2p.exceptions.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Date;
import java.util.Properties;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

public class CertificationAuthority {

	private static int NUM_PEER;

	public static X509Certificate generateAutoCertificate(KeyPair pair)
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

	public static void exportCertificate(X509Certificate cert, String filename)
			throws CertificateEncodingException, IOException {
		PEMWriter pemWr = new PEMWriter(new OutputStreamWriter(
				new FileOutputStream(filename)));
		pemWr.writeObject(cert);
		pemWr.close();
	}

	public static X509Certificate generateCertificate(KeyPair pair,
			X509Certificate caCert, X509Name subjectName)
			throws NoSuchAlgorithmException, CertificateEncodingException,
			InvalidKeyException, IllegalStateException,
			NoSuchProviderException, SignatureException {
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

		return cert;
	}

	public static void initialization()
			throws UnreachableCAConfigurationFileException,
			FileNotFoundException, IOException, WrongCAConfigurationFileSyntaxException
			{

		String configurationFilePath = new String("CA.conf");
		Properties configFile = new Properties();
		// Controllo che il file di configurazione esista e si possa aprire in
		// lettura.
		File file = new File(configurationFilePath);
		if (!file.canRead()) {
			throw new UnreachableCAConfigurationFileException();
		}
		configFile.load(new FileInputStream(configurationFilePath));
		try {
			NUM_PEER = Integer.parseInt(configFile.getProperty("NUM_PEER"));
		} catch (Exception e) {
			throw new WrongCAConfigurationFileSyntaxException();
		}
	}

	public static void main(String[] args) throws CertificateException,
			IOException {

		try {

			/* Lettura del file di configurazione */
			System.out.println("Initialization...");
			initialization();

			/* La CA si autocertifica. */
			String filename = "./ca_certificate.crt";

			// Building keys
			System.out.println("Building keys...");
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA","BC");
			keyPairGen.initialize(1024);
			KeyPair pair = keyPairGen.generateKeyPair();

			// Building my SelfCertificate
			System.out.println("Building certificate...");
			X509Certificate cert = generateAutoCertificate(pair);

			// Basic validation
			System.out.println("Validating dates...");
			cert.checkValidity(new Date());
			System.out.println("Verifying signature...");
			cert.verify(cert.getPublicKey());
			System.out.println("Dates and signature verified.");

			System.out.println("Exporting certificate...");
			exportCertificate(cert, filename);
			System.out.println("Certificate exported.");

			/*
			 * CertificateFactory certFact =
			 * CertificateFactory.getInstance("X.509"); FileInputStream fis =
			 * new FileInputStream("Certificato_CA.crt"); X509Certificate cert =
			 * (X509Certificate) certFact.generateCertificate(fis); fis.close();
			 * System.out.println(cert); cert.checkValidity(new Date()); Key
			 * pubKey = cert.getPublicKey();
			 * System.out.println("Chiave pubblica della Certification Authority: "
			 * ); System.out.println(pubKey.toString());
			 */

			/* CA generates certificates. */
			for (int i = 0; i < NUM_PEER; i++) {
				filename = ("certificate_for_peer_" + i + ".crt");
				X509Name name = new X509Name("CN=Peer" + i);
				X509Certificate certificate = generateCertificate(pair, cert,
						name);
				// Basic validation
				System.out.println("Validating dates...");
				cert.checkValidity(new Date());
				System.out.println("Verifying signature...");
				cert.verify(cert.getPublicKey());
				System.out.println("Dates and signature verified.");

				System.out.println("Exporting certificate...");
				exportCertificate(certificate, filename);
				System.out.println("Certificate exported.");
			}

		} catch (Exception e) {
			System.out.println("EXCEPTION: " + e.getMessage());
		}

	}

}
