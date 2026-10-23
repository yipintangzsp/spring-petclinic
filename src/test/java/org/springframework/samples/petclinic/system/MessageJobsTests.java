/*
 * Copyright 2012-2026 the original author or authors.
 * Licensed under the Apache License, Version 2.0 (the "License").
 */
package org.springframework.samples.petclinic.system;

import java.time.LocalDate;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.web.server.ResponseStatusException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MessageJobsTests {

	private final LocalDate from = LocalDate.parse("2026-01-01");

	private final LocalDate to = LocalDate.parse("2026-12-31");

	private MessageJobs service(JdbcTemplate jdbc) {
		var factory = new StaticListableBeanFactory();
		factory.addBean("jdbc", jdbc);
		return new MessageJobs(factory.getBeanProvider(JdbcTemplate.class));
	}

	private JdbcTemplate database() {
		var jdbc = new JdbcTemplate(
				new DriverManagerDataSource("jdbc:h2:mem:messaging-" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1"));
		jdbc.execute("CREATE SCHEMA clinic_messaging");
		jdbc.execute("""
				CREATE TABLE clinic_messaging.jobs(event_id VARCHAR PRIMARY KEY,idempotency_key VARCHAR UNIQUE,
				kind VARCHAR,payload VARCHAR,status VARCHAR DEFAULT 'queued',attempts INT DEFAULT 0,
				cycle_attempt INT DEFAULT 0,delivery_version INT DEFAULT 1,confirmed_version INT DEFAULT 0,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				next_attempt_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,result VARCHAR,last_error VARCHAR)
				""");
		jdbc.execute("""
				CREATE TABLE clinic_messaging.followups(event_id VARCHAR,visit_id INT,pet_id INT,owner_id INT,
				status VARCHAR,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,completed_at TIMESTAMP)
				""");
		jdbc.execute("""
				CREATE TABLE clinic_messaging.release_audit(release VARCHAR,build INT,source_commit VARCHAR,
				received_at TIMESTAMP)
				""");
		return jdbc;
	}

	@Test
	void unavailableTaskStorageDoesNotBreakTheBusinessApplication() {
		var factory = new StaticListableBeanFactory();
		var service = new MessageJobs(factory.getBeanProvider(JdbcTemplate.class));
		assertThat(service.snapshot().available()).isFalse();
		assertThatThrownBy(() -> service.report("key", this.from, this.to)).isInstanceOf(ResponseStatusException.class);
		assertThat(service(new JdbcTemplate()).snapshot().available()).isFalse();
		assertThat(service(new JdbcTemplate(new DriverManagerDataSource("jdbc:h2:mem:no-messaging"))).snapshot()
			.available()).isFalse();
	}

	@Test
	void sameRequestCreatesOneJobAndConflictingPayloadIsRejected() {
		var jdbc = database();
		var service = service(jdbc);
		String id = service.report("stable-key", this.from, this.to);
		assertThat(service.report("stable-key", this.from, this.to)).isEqualTo(id);
		assertThat(jdbc.queryForObject("SELECT count(*) FROM clinic_messaging.jobs", Long.class)).isEqualTo(1);
		assertThatThrownBy(() -> service.report("stable-key", this.from.plusDays(1), this.to))
			.isInstanceOf(ResponseStatusException.class);
		assertThat(service.job(id).status()).isEqualTo("queued");
		assertThat(service.snapshot().jobs()).hasSize(1);
		assertThat(service.snapshot().counts()).containsEntry("queued", 1L);
	}

	@Test
	void invalidWindowsAndIdentifiersDoNotWriteJobs() {
		var jdbc = database();
		var service = service(jdbc);
		assertThatThrownBy(() -> service.report("key", this.to, this.from)).isInstanceOf(ResponseStatusException.class);
		assertThatThrownBy(() -> service.report("key", this.from.minusYears(1), this.to))
			.isInstanceOf(ResponseStatusException.class);
		assertThatThrownBy(() -> service.report("bad/key", this.from, this.to))
			.isInstanceOf(ResponseStatusException.class);
		assertThatThrownBy(() -> service.job("../invalid")).isInstanceOf(ResponseStatusException.class);
		assertThatThrownBy(() -> service.job("missing")).isInstanceOf(ResponseStatusException.class);
		assertThat(jdbc.queryForObject("SELECT count(*) FROM clinic_messaging.jobs", Long.class)).isZero();
	}

	@Test
	void retryIsBoundedToFailedJobsAndDoesNotOverwriteSuccessfulResults() {
		var jdbc = database();
		var service = service(jdbc);
		String success = service.report("successful", this.from, this.to);
		jdbc.update("UPDATE clinic_messaging.jobs SET status='success',result='retained' WHERE event_id=?", success);
		String failed = service.report("failed", this.from, this.to);
		jdbc.update("""
				UPDATE clinic_messaging.jobs SET status='failed',attempts=3,cycle_attempt=3,delivery_version=4,
				confirmed_version=4,last_error='ValueError' WHERE event_id=?
				""", failed);
		jdbc.update("UPDATE clinic_messaging.jobs SET confirmed_version=3 WHERE event_id=?", failed);
		assertThatThrownBy(() -> service.retry(failed)).isInstanceOf(ResponseStatusException.class);
		jdbc.update("UPDATE clinic_messaging.jobs SET confirmed_version=4 WHERE event_id=?", failed);
		service.retry(failed);
		assertThat(service.job(failed).status()).isEqualTo("queued");
		assertThat(service.job(failed).cycleAttempt()).isZero();
		assertThat(service.job(failed).deliveryVersion()).isEqualTo(5);
		assertThat(service.job(failed).attempts()).isEqualTo(3);
		assertThat(service.job(failed).error()).isNull();
		assertThat(service.job(success).result()).isEqualTo("retained");
		assertThatThrownBy(() -> service.retry(success)).isInstanceOf(ResponseStatusException.class);
		assertThatThrownBy(() -> service.retry(failed)).isInstanceOf(ResponseStatusException.class);
	}

	@Test
	void manualFollowupCompletionIsIdempotent() {
		var jdbc = database();
		var service = service(jdbc);
		String id = service.report("followup-test", this.from, this.to);
		jdbc.update(
				"INSERT INTO clinic_messaging.followups(event_id,visit_id,pet_id,owner_id,status) VALUES (?,1,1,1,'todo')",
				id);
		service.completeFollowup(id);
		var first = jdbc.queryForObject("SELECT completed_at FROM clinic_messaging.followups",
				java.sql.Timestamp.class);
		service.completeFollowup(id);
		assertThat(jdbc.queryForObject("SELECT completed_at FROM clinic_messaging.followups", java.sql.Timestamp.class))
			.isEqualTo(first);
		assertThat(service.snapshot().followups()).hasSize(1);
	}

	@Test
	void metricsDistinguishPendingDeliveryAndUnavailableStorage() {
		var jdbc = database();
		var service = service(jdbc);
		service.report("metrics", this.from, this.to);
		var registry = new io.micrometer.core.instrument.simple.SimpleMeterRegistry();
		new MessageJobMetrics(service).bindTo(registry);
		assertThat(registry.get("petclinic.messaging.storage.available").gauge().value()).isEqualTo(1);
		assertThat(registry.get("petclinic.messaging.outbox.pending").gauge().value()).isEqualTo(1);
		assertThat(registry.get("petclinic.messaging.jobs").tag("status", "queued").gauge().value()).isEqualTo(1);
		assertThat(service.metrics()).isSameAs(service.metrics());
		var factory = new StaticListableBeanFactory();
		var absent = new MessageJobs(factory.getBeanProvider(JdbcTemplate.class));
		assertThat(absent.metrics().available()).isFalse();
		var broken = service(new JdbcTemplate(new DriverManagerDataSource("jdbc:h2:mem:missing-mq-metrics")));
		var missing = new io.micrometer.core.instrument.simple.SimpleMeterRegistry();
		new MessageJobMetrics(broken).bindTo(missing);
		assertThat(missing.get("petclinic.messaging.storage.available").gauge().value()).isZero();
		assertThat(missing.get("petclinic.messaging.outbox.pending").gauge().value()).isNaN();
		assertThat(missing.get("petclinic.messaging.jobs").tag("status", "failed").gauge().value()).isNaN();
	}

}
