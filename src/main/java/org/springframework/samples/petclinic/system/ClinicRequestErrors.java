package org.springframework.samples.petclinic.system;

import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;

@ControllerAdvice(annotations = Controller.class)
class ClinicRequestErrors {

	private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ClinicRequestErrors.class);

	@ExceptionHandler(DataAccessException.class)
	@ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
	String databaseUnavailable(DataAccessException ex) {
		logger.warn("Clinic request could not access the database", ex);
		return "error";
	}

}
