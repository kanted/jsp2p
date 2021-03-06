package it.saccosilvestri.jsp2p.test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import it.saccosilvestri.jsp2p.certificationAuthority.CertificationAuthority;
import it.saccosilvestri.jsp2p.utility.ConfigurationFileUtility;
import it.saccosilvestri.jsp2p.utility.FileUtility;

/**
* @author Sacco Cosimo & Silvestri Davide
*/

public class Trent {

	private static int NUM_PEER;

	/**
	 * Inizializza opportunamente la variabile NUM_PEER
	 * e genera un certificato per ogni peer che partecipera' al test.
	 */
	public static void main(String[] args) {

		try {
			/* Lettura del file di configurazione */
			NUM_PEER = ConfigurationFileUtility.retrieveNumPeer("trent.conf");
			CertificationAuthority ca = new CertificationAuthority();
			for (int i = 0; i < NUM_PEER; i++) {
				ca.generateCertificate(i);
			}
		} catch (Exception e) {
			System.out.println("EXCEPTION: " + e.getClass() + " - "
					+ e.getMessage());
		}
	}
}
