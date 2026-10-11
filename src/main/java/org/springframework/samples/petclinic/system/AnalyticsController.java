/*
 * Copyright 2012-2026 the original author or authors.
 * Licensed under the Apache License, Version 2.0 (the "License").
 */
package org.springframework.samples.petclinic.system;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.List;

import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;

@Controller
class AnalyticsController {

	private final ClinicAnalytics analytics;

	AnalyticsController(ClinicAnalytics analytics) {
		this.analytics = analytics;
	}

	@GetMapping("/insights")
	String insights(@RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate from,
			@RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate to, Model model) {
		LocalDate end = to == null ? LocalDate.now() : to;
		LocalDate start = from == null ? end.minusDays(29) : from;
		if (start.isAfter(end) || ChronoUnit.DAYS.between(start, end) > 365) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Choose a date range of at most 366 days");
		}
		ClinicAnalytics.Snapshot snapshot = this.analytics.snapshot();
		List<ClinicAnalytics.Day> days = snapshot.days()
			.stream()
			.filter(day -> !day.date().isBefore(start) && !day.date().isAfter(end))
			.toList();
		long count = days.stream().mapToLong(ClinicAnalytics.Day::visits).sum();
		long peak = days.stream().mapToLong(ClinicAnalytics.Day::visits).max().orElse(1);
		model.addAttribute("analytics", snapshot);
		model.addAttribute("from", start);
		model.addAttribute("to", end);
		model.addAttribute("days", days);
		model.addAttribute("visitCount", count);
		model.addAttribute("peak", Math.max(1, peak));
		var run = snapshot.run();
		model.addAttribute("outOfWindow", run != null && (start.isBefore(run.start()) || end.isAfter(run.end())));
		return "insights";
	}

}
