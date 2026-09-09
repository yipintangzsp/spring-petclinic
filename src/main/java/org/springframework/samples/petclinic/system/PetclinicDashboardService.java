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

import java.time.Instant;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.SpringBootVersion;
import org.springframework.boot.info.BuildProperties;
import org.springframework.boot.info.GitProperties;
import org.springframework.core.env.Environment;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
class PetclinicDashboardService {

	private static final String BUSINESS_METRICS_SQL = """
			select (select count(*) from owners) as owners,
			       (select count(*) from pets) as pets,
			       (select count(*) from vets) as vets
			""";

	private final JdbcTemplate jdbcTemplate;

	private final BuildProperties buildProperties;

	private final GitProperties gitProperties;

	private final Environment environment;

	PetclinicDashboardService(ObjectProvider<JdbcTemplate> jdbcTemplate,
			ObjectProvider<BuildProperties> buildProperties, ObjectProvider<GitProperties> gitProperties,
			Environment environment) {
		this.jdbcTemplate = jdbcTemplate.getIfAvailable();
		this.buildProperties = buildProperties.getIfAvailable();
		this.gitProperties = gitProperties.getIfAvailable();
		this.environment = environment;
	}

	DashboardSnapshot snapshot() {
		BusinessMetrics metrics = readBusinessMetrics();
		String applicationVersion = firstPresent(environment.getProperty("APPLICATION_VERSION"),
				environment.getProperty("IMAGE_TAG"), buildProperties == null ? null : buildProperties.getVersion(),
				"N/A");
		String buildNumber = firstPresent(environment.getProperty("BUILD_NUMBER"),
				deriveBuildNumber(applicationVersion), "N/A");
		String gitCommit = firstPresent(environment.getProperty("BUILD_GIT_COMMIT"),
				gitProperties == null ? null : gitProperties.getShortCommitId(), "N/A");
		String buildTime = firstPresent(environment.getProperty("BUILD_TIME"),
				buildProperties == null ? null : format(buildProperties.getTime()), "N/A");
		boolean kubernetes = environment.getProperty("KUBERNETES_SERVICE_HOST") != null;

		return new DashboardSnapshot(metrics, "UP", SpringBootVersion.getVersion(),
				metrics.available() ? "Connected" : "Unavailable", kubernetes ? "Detected" : "Local runtime",
				applicationVersion, buildNumber, gitCommit, buildTime, kubernetes ? "Kubernetes" : "Local");
	}

	private BusinessMetrics readBusinessMetrics() {
		if (this.jdbcTemplate == null) {
			return new BusinessMetrics(0, 0, 0, false);
		}
		try {
			return jdbcTemplate.queryForObject(BUSINESS_METRICS_SQL, (rs,
					rowNum) -> new BusinessMetrics(rs.getLong("owners"), rs.getLong("pets"), rs.getLong("vets"), true));
		}
		catch (DataAccessException ex) {
			return new BusinessMetrics(0, 0, 0, false);
		}
	}

	private static String deriveBuildNumber(String version) {
		int marker = version.lastIndexOf("-ci-");
		return marker >= 0 ? version.substring(marker + 4) : null;
	}

	private static String format(Instant instant) {
		return instant == null ? null : instant.toString();
	}

	private static String firstPresent(String... candidates) {
		for (String candidate : candidates) {
			if (candidate != null && !candidate.isBlank()) {
				return candidate;
			}
		}
		return "N/A";
	}

	record BusinessMetrics(long owners, long pets, long vets, boolean available) {
	}

	record DashboardSnapshot(BusinessMetrics metrics, String applicationStatus, String springBootVersion,
			String databaseStatus, String kubernetesStatus, String applicationVersion, String buildNumber,
			String gitCommit, String buildTime, String environment) {
	}

}
