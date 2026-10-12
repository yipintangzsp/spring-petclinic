/*
 * Copyright 2012-2026 the original author or authors.
 * Licensed under the Apache License, Version 2.0 (the "License").
 */
package org.springframework.samples.petclinic.system;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

class ClinicAnalyticsTests {

	private ClinicAnalytics analytics(JdbcTemplate jdbc) {
		var factory = new StaticListableBeanFactory();
		factory.addBean("jdbc", jdbc);
		return new ClinicAnalytics(factory.getBeanProvider(JdbcTemplate.class));
	}

	@Test
	void noDatabaseBeanDoesNotBreakTheApplication() {
		var factory = new StaticListableBeanFactory();
		var snapshot = new ClinicAnalytics(factory.getBeanProvider(JdbcTemplate.class)).snapshot();
		assertThat(snapshot.available()).isFalse();
		assertThat(snapshot.failed()).isTrue();
		var registry = new SimpleMeterRegistry();
		new ClinicAnalysisMetrics(new ClinicAnalytics(factory.getBeanProvider(JdbcTemplate.class))).bindTo(registry);
		assertThat(registry.get("petclinic.analysis.available").gauge().value()).isZero();
		assertThat(registry.get("petclinic.analysis.last.success.seconds").gauge().value()).isZero();
		assertThat(registry.get("petclinic.analysis.window.visits").gauge().value()).isNaN();
	}

	@Test
	void aTemplateWithoutDataSourceDoesNotBreakTheApplication() {
		var snapshot = analytics(new JdbcTemplate()).snapshot();
		assertThat(snapshot.available()).isFalse();
		assertThat(snapshot.failed()).isTrue();
	}

	@Test
	void missingAnalysisSchemaDoesNotFailBusinessPage() {
		JdbcTemplate jdbc = new JdbcTemplate(new DriverManagerDataSource("jdbc:h2:mem:analytics-missing"));
		var snapshot = analytics(jdbc).snapshot();
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
		var analytics = analytics(jdbc);
		var registry = new SimpleMeterRegistry();
		new ClinicAnalysisMetrics(analytics).bindTo(registry);
		var first = analytics.snapshot();
		assertThat(registry.get("petclinic.analysis.available").gauge().value()).isEqualTo(1);
		assertThat(registry.get("petclinic.analysis.read.failed").gauge().value()).isZero();
		assertThat(registry.get("petclinic.analysis.last.success.seconds").gauge().value()).isPositive();
		assertThat(registry.get("petclinic.analysis.window.visits").gauge().value()).isEqualTo(7);
		assertThat(first.available()).isTrue();
		assertThat(first.run().owners()).isEqualTo(200);
		assertThat(first.days().get(0).visits()).isEqualTo(7);
		jdbc.execute("DROP TABLE petclinic_analytics.runs");
		assertThat(analytics.snapshot()).isSameAs(first);
		ReflectionTestUtils.setField(analytics, "checked", 0L);
		var stale = analytics.snapshot();
		assertThat(stale.available()).isTrue();
		assertThat(stale.failed()).isTrue();
		assertThat(stale.run()).isEqualTo(first.run());
		assertThat(stale.days()).isEqualTo(first.days());
		assertThat(registry.get("petclinic.analysis.available").gauge().value()).isEqualTo(1);
		assertThat(registry.get("petclinic.analysis.read.failed").gauge().value()).isEqualTo(1);
		assertThat(registry.get("petclinic.analysis.window.visits").gauge().value()).isEqualTo(7);
	}

}
