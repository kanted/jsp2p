package it.saccosilvestri.jsp2p.exceptions;

import it.saccosilvestri.jsp2p.logging.LogManager;

/**
* @author Sacco Cosimo & Silvestri Davide
*/

public class BadNonceException extends Exception {

	public String getMessage() {
		return "Received nonce is different from the one sent.";

	}
	
	public BadNonceException(){
		LogManager.currentLogger.error("Received nonce is different from the one sent.");
	}

}
