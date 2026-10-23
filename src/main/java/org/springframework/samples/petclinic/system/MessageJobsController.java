/*
 * Copyright 2012-2026 the original author or authors.
 * Licensed under the Apache License, Version 2.0 (the "License").
 */
package org.springframework.samples.petclinic.system;

import java.time.LocalDate;
import java.util.UUID;

import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

@Controller
class MessageJobsController {

	private static final String REDIRECT_JOBS = "redirect:/jobs";

	private final MessageJobs jobs;

	MessageJobsController(MessageJobs jobs) {
		this.jobs = jobs;
	}

	@GetMapping("/jobs")
	String page(Model model) {
		model.addAttribute("messaging", this.jobs.snapshot());
		model.addAttribute("requestKey", UUID.randomUUID().toString());
		model.addAttribute("reportFrom", LocalDate.now().withDayOfYear(1));
		model.addAttribute("reportTo", LocalDate.now().withMonth(12).withDayOfMonth(31));
		return "jobs";
	}

	@PostMapping("/jobs/reports")
	String report(@RequestParam String key, @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate from,
			@RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate to) {
		this.jobs.report(key, from, to);
		return REDIRECT_JOBS;
	}

	@PostMapping("/api/messaging/reports")
	@ResponseStatus(HttpStatus.ACCEPTED)
	@ResponseBody
	MessageJobs.Job apiReport(@RequestParam String key,
			@RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate from,
			@RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate to) {
		return this.jobs.job(this.jobs.report(key, from, to));
	}

	@GetMapping("/api/messaging/jobs/{id}")
	@ResponseBody
	MessageJobs.Job status(@PathVariable String id) {
		return this.jobs.job(id);
	}

	@PostMapping("/jobs/{id}/retry")
	String retry(@PathVariable String id) {
		this.jobs.retry(id);
		return REDIRECT_JOBS;
	}

	@PostMapping("/jobs/followups/{id}/complete")
	String complete(@PathVariable String id) {
		this.jobs.completeFollowup(id);
		return REDIRECT_JOBS;
	}

}
