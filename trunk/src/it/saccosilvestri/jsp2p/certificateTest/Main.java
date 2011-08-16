package it.saccosilvestri.jsp2p.certificateTest;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

public class Main {

	public static void main(String[] args) throws CertificateException, IOException {
		CertificateFactory certFact = CertificateFactory.getInstance("X.509");
		FileInputStream fis = new FileInputStream("Certificato_CA.crt");
		Certificate cert = certFact.generateCertificate(fis);
		fis.close();
		System.out.println(cert);
	}
	
}
