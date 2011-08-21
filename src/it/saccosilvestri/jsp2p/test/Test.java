package it.saccosilvestri.jsp2p.test;

import it.saccosilvestri.jsp2p.certificationAuthority.CertificationAuthority;
import it.saccosilvestri.jsp2p.exceptions.UnreachableCAConfigurationFileException;
import it.saccosilvestri.jsp2p.exceptions.WrongCAConfigurationFileSyntaxException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyPair;
import java.util.Properties;

public class Test {

	private static int NUM_PEER;

	public static void initialization()
			throws UnreachableCAConfigurationFileException,
			FileNotFoundException, IOException,
			WrongCAConfigurationFileSyntaxException {

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
			NUM_PEER = 1;// TODO
							// Integer.parseInt(configFile.getProperty("NUM_PEER"));
		} catch (Exception e) {
			throw new WrongCAConfigurationFileSyntaxException();
		}
	}

	public static void main(String[] args) {

		try {
			/* Lettura del file di configurazione */
			System.out.println("Initialization...");
			initialization();

			CertificationAuthority ca = new CertificationAuthority();
			System.out.println("Starting simulation");
			for (int i = 0; i < NUM_PEER; i++) {
				System.out.println("porta " + 8000 + i);
				KeyPair kp = ca.generateCertificate(i);
				TestThread a = new TestThread("certificate_for_peer_" + i
						+ ".crt", "ca_certificate.crt", 8000 + i, true, kp);
			}
			for (int i = 0; i < NUM_PEER; i++) {
				KeyPair kp = ca.generateCertificate(i);
				TestThread b = new TestThread("certificate_for_peer_" + i
						+ ".crt", "ca_certificate.crt", 8000 + i, false, kp);
			}
		} catch (Exception e) {
			System.out.println("EXCEPTION: " + e.getClass() + " - " + e.getMessage());
		}
	}

}
