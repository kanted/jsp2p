package it.saccosilvestri.jsp2p.exceptions;

import it.saccosilvestri.jsp2p.logging.LogManager;

/**
* @author Sacco Cosimo & Silvestri Davide
*/

public class BadHashCodeException extends Exception {

	public String getMessage() {
		return "Bad hash.";

	}
	
	public BadHashCodeException(){
		LogManager.currentLogger.error("Bad hash.");
	}

}
