/*
 * Copyright 2012-2026 the original author or authors.
 * Licensed under the Apache License, Version 2.0 (the "License").
 */
package org.springframework.samples.petclinic.system;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

class ClinicAnalyticsTests {

	@Test
	void missingAnalysisSchemaDoesNotFailBusinessPage() {
		JdbcTemplate jdbc = new JdbcTemplate(new DriverManagerDataSource("jdbc:h2:mem:analytics-missing"));
		var snapshot = new ClinicAnalytics(jdbc).snapshot();
		assertThat(snapshot.available()).isFalse();
		assertThat(snapshot.failed()).isTrue();
	}

	@Test
	void preserveSuccessfulSnapshotWhenDatabaseReadFails() {
		JdbcTemplate jdbc = new JdbcTemplate(
				new DriverManagerDataSource("jdbc:h2:mem:analytics-cache;DB_CLOSE_DELAY=-1"));
		jdbc.execute("CREATE SCHEMA petclinic_analytics");
		jdbc.execute("""
				CREATE TABLE petclinic_analytics.runs (run_id VARCHAR, generated_at TIMESTAMP,
				window_start DATE, window_end DATE, source_kind VARCHAR, owners BIGINT, pets BIGINT,
				vets BIGINT, visits BIGINT, status VARCHAR)
				""");
		jdbc.execute("CREATE TABLE petclinic_analytics.daily_visits (run_id VARCHAR, stat_date DATE, visits BIGINT)");
		jdbc.execute("CREATE TABLE petclinic_analytics.pet_types (run_id VARCHAR, type VARCHAR, pets BIGINT)");
		jdbc.execute("""
				INSERT INTO petclinic_analytics.runs VALUES ('success','2026-10-11 00:00:00',
				'2026-01-01','2026-12-31','demo',200,350,20,1200,'success')
				""");
		jdbc.execute("INSERT INTO petclinic_analytics.daily_visits VALUES ('success','2026-10-01',7)");
		jdbc.execute("INSERT INTO petclinic_analytics.pet_types VALUES ('success','dog',350)");
		var analytics = new ClinicAnalytics(jdbc);
		var first = analytics.snapshot();
		assertThat(first.available()).isTrue();
		assertThat(first.run().owners()).isEqualTo(200);
		assertThat(first.days().get(0).visits()).isEqualTo(7);
		jdbc.execute("DROP TABLE petclinic_analytics.runs");
		ReflectionTestUtils.setField(analytics, "checked", 0L);
		var stale = analytics.snapshot();
		assertThat(stale.available()).isTrue();
		assertThat(stale.failed()).isTrue();
		assertThat(stale.run()).isEqualTo(first.run());
		assertThat(stale.days()).isEqualTo(first.days());
	}

}
