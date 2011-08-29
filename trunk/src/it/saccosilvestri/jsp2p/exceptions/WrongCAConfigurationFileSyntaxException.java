package it.saccosilvestri.jsp2p.exceptions;

import it.saccosilvestri.jsp2p.logging.LogManager;

/**
* @author Sacco Cosimo & Silvestri Davide
*/

public class WrongCAConfigurationFileSyntaxException extends Exception {

	public String getMessage() {
		return "Wrong CA Configuration File syntax.";
	}
	
	public WrongCAConfigurationFileSyntaxException(){
		LogManager.currentLogger.fatal("Wrong CA Configuration File syntax.");
	}
}
