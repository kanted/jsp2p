package it.saccosilvestri.jsp2p.test;

import java.security.KeyPair;

import it.saccosilvestri.jsp2p.certificationAuthority.CertificationAuthority;
import it.saccosilvestri.jsp2p.utility.ConfigurationFileUtility;

public class Main {

	private static int NUM_PEER;

	public static void main(String[] args) {

		try {
			/* Lettura del file di configurazione */
			System.out.println("Initialization...");
			NUM_PEER = ConfigurationFileUtility.retrieveNumPeer();

			CertificationAuthority ca = new CertificationAuthority(); 
			
			System.out.println("Generating and exporting certificates for peers...");
			for (int i = 0; i < NUM_PEER; i++) {
				KeyPair kp = ca.generateCertificate(i);
				Peer peer = new Peer(i,kp);
			}
			
			
		} catch (Exception e) {
			System.out.println("EXCEPTION: " + e.getClass() + " - " + e.getMessage());
		}
	}
}
