/*
 * Copyright 2012-2026 the original author or authors.
 * Licensed under the Apache License, Version 2.0 (the "License").
 */
package org.springframework.samples.petclinic.system;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import javax.sql.DataSource;

import org.springframework.dao.DataAccessException;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
class ClinicAnalytics {

	private final @Nullable JdbcTemplate jdbc;

	private Snapshot cached;

	private long checked;

	@Autowired
	ClinicAnalytics(ObjectProvider<JdbcTemplate> templates) {
		JdbcTemplate available = templates.getIfAvailable();
		DataSource dataSource = available == null ? null : available.getDataSource();
		if (dataSource == null) {
			this.jdbc = null;
		}
		else {
			this.jdbc = new JdbcTemplate(dataSource);
			this.jdbc.setQueryTimeout(3);
		}
	}

	synchronized Snapshot snapshot() {
		if (this.jdbc == null) {
			return new Snapshot(null, List.of(), List.of(), null, false, true);
		}
		if (this.checked != 0 && System.nanoTime() - this.checked < 15_000_000_000L) {
			return this.cached;
		}
		this.checked = System.nanoTime();
		try {
			Execution execution = latestExecution();
			List<Run> runs = this.jdbc.query("""
					SELECT run_id, generated_at, window_start, window_end, source_kind, owners, pets, vets, visits
					FROM petclinic_analytics.runs WHERE status = 'success' ORDER BY generated_at DESC LIMIT 1
					""",
					(rs, n) -> new Run(rs.getString("run_id"), rs.getTimestamp("generated_at").toInstant(),
							rs.getDate("window_start").toLocalDate(), rs.getDate("window_end").toLocalDate(),
							rs.getString("source_kind"), rs.getLong("owners"), rs.getLong("pets"), rs.getLong("vets"),
							rs.getLong("visits")));
			if (runs.isEmpty()) {
				this.cached = new Snapshot(null, List.of(), List.of(), execution, false, false);
			}
			else {
				Run run = runs.get(0);
				List<Day> days = this.jdbc.query("""
						SELECT stat_date, visits FROM petclinic_analytics.daily_visits
						WHERE run_id = ? ORDER BY stat_date LIMIT 367
						""", (rs, n) -> new Day(rs.getDate("stat_date").toLocalDate(), rs.getLong("visits")), run.id());
				List<Type> types = this.jdbc.query("""
						SELECT type, pets FROM petclinic_analytics.pet_types
						WHERE run_id = ? ORDER BY pets DESC, type LIMIT 64
						""", (rs, n) -> new Type(rs.getString("type"), rs.getLong("pets")), run.id());
				this.cached = new Snapshot(run, days, types, execution, true, false);
			}
		}
		catch (DataAccessException ex) {
			this.cached = this.cached != null && this.cached.available() ? new Snapshot(this.cached.run(),
					this.cached.days(), this.cached.types(), this.cached.execution(), true, true)
					: new Snapshot(null, List.of(), List.of(), null, false, true);
		}
		return this.cached;
	}

	private @Nullable Execution latestExecution() {
		try {
			List<Execution> rows = this.jdbc.query("""
					SELECT batch_id, status, stage, started_at, finished_at, error
					FROM petclinic_analytics.executions ORDER BY started_at DESC LIMIT 1
					""",
					(rs, n) -> new Execution(rs.getString("batch_id"), rs.getString("status"), rs.getString("stage"),
							rs.getTimestamp("started_at").toInstant(),
							rs.getTimestamp("finished_at") == null ? null : rs.getTimestamp("finished_at").toInstant(),
							rs.getString("error")));
			return rows.isEmpty() ? null : rows.get(0);
		}
		catch (DataAccessException ignored) {
			// The application and additive orchestration schema can be rolled out
			// independently.
			return null;
		}
	}

	record Run(String id, Instant generatedAt, LocalDate start, LocalDate end, String sourceKind, long owners,
			long pets, long vets, long visits) {
	}

	record Day(LocalDate date, long visits) {
	}

	record Type(String name, long pets) {
	}

	record Execution(String batchId, String status, String stage, Instant startedAt, @Nullable Instant finishedAt,
			@Nullable String error) {
	}

	record Snapshot(@Nullable Run run, List<Day> days, List<Type> types, @Nullable Execution execution,
			boolean available, boolean failed) {
	}

}
