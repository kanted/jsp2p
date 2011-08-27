package it.saccosilvestri.jsp2p.utility;

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
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.openssl.PEMWriter;

public class CertificateVerificationUtility {

	public static void checkCertificate(X509Certificate cert, PublicKey pk) throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		System.out.println("Controllo la data.");
		cert.checkValidity(new Date());
		System.out.println("Controllo la firma.");
		cert.verify(pk);
		System.out.println("Controlli eseguiti correttamente.");
	}
	
	public static void checkAndExportCertificate(X509Certificate cert, PublicKey pk, String filename) throws IOException, InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException{
		checkCertificate(cert,pk);
		System.out.println("Esporto il certificato.");
		PEMWriter pemWr = new PEMWriter(new OutputStreamWriter(
				new FileOutputStream(filename)));
		pemWr.writeObject(cert);
		pemWr.close();
		System.out.println("Certificato esportato.");
	}
	
}
