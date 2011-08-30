package it.saccosilvestri.jsp2p.certificationAuthority;

import it.saccosilvestri.jsp2p.exceptions.UnreachableLoggerConfigurationFileException;
import it.saccosilvestri.jsp2p.logging.LogManager;
import it.saccosilvestri.jsp2p.utility.CertificateUtility;
import it.saccosilvestri.jsp2p.utility.FileUtility;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;

/**
* @brief Servizio per la creazione dei certificati e delle chiavi pubbliche e private per i peer.
* @author Sacco Cosimo & Silvestri Davide
*/

public class CertificationAuthority {

	private KeyPair pair;
	X509Certificate caCert;

	 /**
     * Genera il certificato per la CA, firmato dalla CA stessa.
     */
	private X509Certificate selfCertificate(KeyPair pair)
			throws InvalidKeyException, NoSuchProviderException,
			SignatureException, NoSuchAlgorithmException,
			CertificateEncodingException, IllegalStateException {

		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

		certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		certGen.setIssuerDN(new X509Name("CN=Pippo"));
		certGen.setNotBefore(new Date(
				System.currentTimeMillis() - 50000 * 60 * 60));
		certGen.setNotAfter(new Date(System.currentTimeMillis() + 50000 * 60
				* 60 * 24));
		certGen.setSubjectDN(new X509Name("CN=Pippo"));
		certGen.setPublicKey(pair.getPublic());
		certGen.setSignatureAlgorithm("SHA1WithRSAEncryption");

		return certGen.generate(pair.getPrivate());
	}

	 /**
     * Genera la chiava pubblica, la chiave privata ed il certificato per il peer i-esimo, firmato dalla CA.
     */
	public void generateCertificate(int i) throws NoSuchAlgorithmException,
			InvalidKeyException, IllegalStateException,
			NoSuchProviderException, SignatureException, CertificateException,
			IOException, InvalidKeySpecException {
		String filename = ("certificate_for_peer_" + i + ".crt");
		X509Name subjectName = new X509Name("CN=Peer" + i);
		Date startDate = new Date(System.currentTimeMillis() - 50000 * 60 * 60);
		Date expiryDate = new Date(System.currentTimeMillis() + 50000 * 60 * 60
				* 24);
		BigInteger serialNumber = BigInteger
				.valueOf(System.currentTimeMillis()); 
		PrivateKey caKey = pair.getPrivate(); 
		// Building keys
		LogManager.currentLogger.info("Building keys...");
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
		keyPairGen.initialize(1024);
		KeyPair keyPair = keyPairGen.generateKeyPair(); 
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

		certGen.setSerialNumber(serialNumber);
		certGen.setIssuerDN((X509Name) caCert.getIssuerDN());
		certGen.setNotBefore(startDate);
		certGen.setNotAfter(expiryDate);
		certGen.setSubjectDN(subjectName);
		certGen.setPublicKey(keyPair.getPublic());
		certGen.setSignatureAlgorithm("SHA1WithRSAEncryption");
		X509Certificate cert = certGen.generate(caKey); 
		
		KeyFactory fact = KeyFactory.getInstance("RSA", "BC");
		RSAPublicKeySpec pub = (RSAPublicKeySpec) fact.getKeySpec(
				keyPair.getPublic(), RSAPublicKeySpec.class);
		RSAPrivateKeySpec priv = (RSAPrivateKeySpec) fact.getKeySpec(
				keyPair.getPrivate(), RSAPrivateKeySpec.class);

		// Checking and exporting
		CertificateUtility.checkAndExportCertificate(cert,
				caCert.getPublicKey(), filename);
		FileUtility.saveKeyToFile("public" + i + ".key", pub.getModulus(),
				pub.getPublicExponent());
		FileUtility.saveKeyToFile("private" + i + ".key", priv.getModulus(),
				priv.getPrivateExponent());

	}

	/**
     * La CA si autocertifica ed esporta il suo certificato.
     */
	public CertificationAuthority() throws NoSuchAlgorithmException,
			NoSuchProviderException, InvalidKeyException, SignatureException,
			IllegalStateException, CertificateException, IOException, UnreachableLoggerConfigurationFileException {
		
		LogManager.initialization("ca_logger.conf");
		LogManager.currentLogger.info("STARTING CA.");
		String filename = "./ca_certificate.crt";

		// Keys
		LogManager.currentLogger.info("Building keys...");
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
		keyPairGen.initialize(1024);
		pair = keyPairGen.generateKeyPair();

		// SelfCertificate
		LogManager.currentLogger.info("Building certificate...");
		caCert = selfCertificate(pair);

		// Check and export
		CertificateUtility.checkAndExportCertificate(caCert,
				caCert.getPublicKey(), filename);

	}

}