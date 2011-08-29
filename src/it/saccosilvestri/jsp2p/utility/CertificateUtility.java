package it.saccosilvestri.jsp2p.utility;

import it.saccosilvestri.jsp2p.exceptions.WrongSubjectDNException;
import it.saccosilvestri.jsp2p.logging.LogManager;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.openssl.PEMWriter;

/**
* @author Sacco Cosimo & Silvestri Davide
*/

public class CertificateUtility {

	/**
	 * Controlla validita' e scandenza del certificato.
	 */
	public static void checkCertificate(X509Certificate cert, PublicKey pk)
			throws InvalidKeyException, CertificateException,
			NoSuchAlgorithmException, NoSuchProviderException,
			SignatureException {
		LogManager.currentLogger.warn("Attenzione! Certificato rilasciato a: "+cert.getSubjectDN());
		cert.checkValidity(new Date());
		LogManager.currentLogger.info("Controllo la firma.");
		cert.verify(pk);
		LogManager.currentLogger.info("Controlli eseguiti correttamente.");
	}
	
	/**
	 * Controlla validita' e scandenza del certificato.
	 * Inoltre controlla che il certificato sia stato rilasciato
	 * al peer il cui id e' passato come argomento.
	 */
	public static void checkCertificateWithNameAuthentication(X509Certificate cert, PublicKey pk, String peerName) throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException{
		LogManager.currentLogger.info("Controllo che il certificato sia stato rilasciato a: "+peerName+".");
		if (peerName.compareTo((cert.getSubjectDN().getName()))!=0)
			throw new WrongSubjectDNException();
		checkCertificate(cert,pk);
	}

	/**
	 * Controlla validita' e scandenza del certificato.
	 * Inoltre lo salva su file.
	 */
	public static void checkAndExportCertificate(X509Certificate cert,
			PublicKey pk, String filename) throws IOException,
			InvalidKeyException, CertificateException,
			NoSuchAlgorithmException, NoSuchProviderException,
			SignatureException {
		checkCertificate(cert, pk);
		LogManager.currentLogger.info("Esporto il certificato.");
		PEMWriter pemWr = new PEMWriter(new OutputStreamWriter(
				new FileOutputStream(filename)));
		pemWr.writeObject(cert);
		pemWr.close();
		LogManager.currentLogger.info("Certificato esportato.");
	}

	/**
	 * Legge da file un certificato.
	 */
	public static X509Certificate readCertificate(String filename)
			throws FileNotFoundException, CertificateException,
			NoSuchProviderException {
		FileInputStream f = new FileInputStream(filename);
		CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
		return (X509Certificate) fact.generateCertificate(f);
	}

}
