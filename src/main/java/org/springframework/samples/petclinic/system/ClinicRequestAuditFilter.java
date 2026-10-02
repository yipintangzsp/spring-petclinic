/*
 * Copyright 2012-2025 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 */

package org.springframework.samples.petclinic.system;

import java.io.IOException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerMapping;

@Component
@Order(Ordered.LOWEST_PRECEDENCE - 10)
class ClinicRequestAuditFilter extends OncePerRequestFilter {

	private static final Logger log = LoggerFactory.getLogger(ClinicRequestAuditFilter.class);

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) {
		return request.getRequestURI().startsWith("/actuator/") || request.getRequestURI().startsWith("/resources/")
				|| request.getRequestURI().startsWith("/webjars/");
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		long started = System.nanoTime();
		boolean failed = false;
		try {
			chain.doFilter(request, response);
		}
		catch (ServletException | IOException | RuntimeException ex) {
			failed = true;
			throw ex;
		}
		finally {
			Object route = request.getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE);
			log.atInfo()
				.addKeyValue("event.dataset", "petclinic.http")
				.addKeyValue("event.action", "http_request")
				.addKeyValue("http.request.method", request.getMethod())
				.addKeyValue("http.route", route == null ? "unmatched" : route.toString())
				.addKeyValue("http.response.status_code", failed ? 500 : response.getStatus())
				.addKeyValue("event.duration", System.nanoTime() - started)
				.log("Petclinic request completed");
		}
	}

}
