/*
 * Copyright 2012-2026 the original author or authors.
 * Licensed under the Apache License, Version 2.0 (the "License").
 */
package org.springframework.samples.petclinic.system;

import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
class MessageJobs {

	private final @Nullable JdbcTemplate jdbc;

	MessageJobs(ObjectProvider<JdbcTemplate> templates) {
		JdbcTemplate source = templates.getIfAvailable();
		if (source == null || source.getDataSource() == null) {
			this.jdbc = null;
		}
		else {
			this.jdbc = new JdbcTemplate(source.getDataSource());
			this.jdbc.setQueryTimeout(3);
		}
	}

	record Job(String id, String kind, String status, int attempts, int cycleAttempt, int deliveryVersion,
			int confirmedVersion, String updatedAt, @Nullable String result, @Nullable String error) {
	}

	record Snapshot(boolean available, List<Job> jobs, List<Map<String, Object>> followups,
			List<Map<String, Object>> releases, Map<String, Long> counts) {
	}

	Snapshot snapshot() {
		if (this.jdbc == null) {
			return new Snapshot(false, List.of(), List.of(), List.of(), Map.of());
		}
		try {
			List<Job> jobs = this.jdbc.query("""
					SELECT event_id,kind,status,attempts,cycle_attempt,delivery_version,confirmed_version,
					updated_at,result,last_error FROM clinic_messaging.jobs ORDER BY updated_at DESC LIMIT 30
					""",
					(rs, n) -> new Job(rs.getString(1), rs.getString(2), rs.getString(3), rs.getInt(4), rs.getInt(5),
							rs.getInt(6), rs.getInt(7), rs.getTimestamp(8).toInstant().toString(), rs.getString(9),
							rs.getString(10)));
			List<Map<String, Object>> followups = this.jdbc.queryForList("""
					SELECT event_id,visit_id,pet_id,owner_id,status,created_at,completed_at
					FROM clinic_messaging.followups ORDER BY created_at DESC LIMIT 20
					""");
			List<Map<String, Object>> releases = this.jdbc.queryForList("""
					SELECT release,build,source_commit,received_at FROM clinic_messaging.release_audit
					ORDER BY received_at DESC LIMIT 10
					""");
			Map<String, Long> counts = new java.util.HashMap<>();
			this.jdbc.query("SELECT status,count(*) FROM clinic_messaging.jobs GROUP BY status", rs -> {
				counts.put(rs.getString(1), rs.getLong(2));
			});
			return new Snapshot(true, jobs, followups, releases, counts);
		}
		catch (DataAccessException ex) {
			return new Snapshot(false, List.of(), List.of(), List.of(), Map.of());
		}
	}

	Job job(String id) {
		if (!id.matches("[A-Za-z0-9_-]{1,128}")) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid job identifier");
		}
		List<Job> rows = required().query("""
				SELECT event_id,kind,status,attempts,cycle_attempt,delivery_version,confirmed_version,
				updated_at,result,last_error FROM clinic_messaging.jobs WHERE event_id=?
				""",
				(rs, n) -> new Job(rs.getString(1), rs.getString(2), rs.getString(3), rs.getInt(4), rs.getInt(5),
						rs.getInt(6), rs.getInt(7), rs.getTimestamp(8).toInstant().toString(), rs.getString(9),
						rs.getString(10)),
				id);
		if (rows.isEmpty()) {
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Job not found");
		}
		return rows.get(0);
	}

	String report(String key, LocalDate from, LocalDate to) {
		if (!key.matches("[A-Za-z0-9_-]{1,80}") || from.isAfter(to) || ChronoUnit.DAYS.between(from, to) > 365) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
					"Use a unique key and at most 366 inclusive days");
		}
		String id = "report-" + UUID.nameUUIDFromBytes(key.getBytes(StandardCharsets.UTF_8));
		String payload = "{\"from\":\"" + from + "\",\"to\":\"" + to + "\"}";
		try {
			required().update("""
					INSERT INTO clinic_messaging.jobs(event_id,idempotency_key,kind,payload)
					VALUES (?,?,'statistics_report',?)
					""", id, "report-" + key, payload);
		}
		catch (DuplicateKeyException ex) {
			String existing = required().queryForObject("SELECT payload FROM clinic_messaging.jobs WHERE event_id=?",
					String.class, id);
			if (!payload.equals(existing)) {
				throw new ResponseStatusException(HttpStatus.CONFLICT, "This key already names a different report");
			}
		}
		return id;
	}

	void retry(String id) {
		Job current = job(id);
		if (!"failed".equals(current.status()) || required().update(
				"""
						UPDATE clinic_messaging.jobs SET status='queued',cycle_attempt=0,
						delivery_version=delivery_version+1,next_attempt_at=CURRENT_TIMESTAMP,
						last_error=NULL,updated_at=CURRENT_TIMESTAMP WHERE event_id=? AND status='failed' AND confirmed_version=delivery_version
						""",
				id) != 1) {
			throw new ResponseStatusException(HttpStatus.CONFLICT,
					"Only failed jobs with confirmed dead-letter delivery can be retried");
		}
	}

	void completeFollowup(String id) {
		job(id);
		required().update("""
				UPDATE clinic_messaging.followups SET status='done',completed_at=CURRENT_TIMESTAMP
				WHERE event_id=? AND status='todo'
				""", id);
	}

	record Metrics(boolean available, Map<String, Long> counts, long pending) {
	}

	private Metrics measured = new Metrics(false, Map.of(), 0);

	private long measuredAt;

	synchronized Metrics metrics() {
		if (this.jdbc == null) {
			return this.measured;
		}
		if (this.measuredAt != 0 && System.nanoTime() - this.measuredAt < 10_000_000_000L) {
			return this.measured;
		}
		this.measuredAt = System.nanoTime();
		try {
			Map<String, Long> counts = new java.util.HashMap<>();
			this.jdbc.query("SELECT status,count(*) FROM clinic_messaging.jobs GROUP BY status", rs -> {
				counts.put(rs.getString(1), rs.getLong(2));
			});
			Long pending = this.jdbc.queryForObject(
					"SELECT count(*) FROM clinic_messaging.jobs WHERE confirmed_version < delivery_version",
					Long.class);
			this.measured = new Metrics(true, counts, pending == null ? 0 : pending);
		}
		catch (DataAccessException ex) {
			this.measured = new Metrics(false, Map.of(), 0);
		}
		return this.measured;
	}

	private JdbcTemplate required() {
		if (this.jdbc == null) {
			throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Message task storage unavailable");
		}
		return this.jdbc;
	}

}
