package it.saccosilvestri.jsp2p.test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import it.saccosilvestri.jsp2p.certificationAuthority.CertificationAuthority;
import it.saccosilvestri.jsp2p.utility.ConfigurationFileUtility;
import it.saccosilvestri.jsp2p.utility.FileUtility;

public class Main {

	private static int NUM_PEER;

	public static void main(String[] args) {

		try {
			/* Lettura del file di configurazione */
			System.out.println("Initialization...");
			NUM_PEER = ConfigurationFileUtility.retrieveNumPeer();

			CertificationAuthority ca = new CertificationAuthority(); 
			
			System.out.println("Generating and exporting certificates and keys for peers...");
			for (int i = 0; i < NUM_PEER; i++) {
				ca.generateCertificate(i);
			}
			
			
		} catch (Exception e) {
			System.out.println("EXCEPTION: " + e.getClass() + " - " + e.getMessage());
		}
	}
}
