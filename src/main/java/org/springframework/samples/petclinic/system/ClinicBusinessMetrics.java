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

import java.util.Map;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.MeterBinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
class ClinicBusinessMetrics implements MeterBinder {

	private static final Logger log = LoggerFactory.getLogger(ClinicBusinessMetrics.class);

	private final JdbcTemplate jdbc;

	private Map<String, Object> counts = Map.of();

	private long refreshed;

	private boolean available;

	ClinicBusinessMetrics(ObjectProvider<JdbcTemplate> jdbc) {
		this.jdbc = jdbc.getIfAvailable();
	}

	@Override
	public void bindTo(MeterRegistry registry) {
		for (String entity : new String[] { "owners", "pets", "vets", "visits" }) {
			Gauge.builder("petclinic.business.records", this, metrics -> metrics.count(entity))
				.tag("entity", entity)
				.description("Database record counts; aggregate once across replicas")
				.register(registry);
		}
		Gauge.builder("petclinic.business.database.available", this, metrics -> metrics.databaseAvailable())
			.register(registry);
	}

	synchronized double count(String entity) {
		refresh();
		return this.available ? ((Number) this.counts.get(entity)).doubleValue() : Double.NaN;
	}

	synchronized double databaseAvailable() {
		refresh();
		return this.available ? 1 : 0;
	}

	private void refresh() {
		long now = System.nanoTime();
		if (this.refreshed != 0 && now - this.refreshed < 30_000_000_000L) {
			return;
		}
		this.refreshed = now;
		try {
			if (this.jdbc == null) {
				this.available = false;
				return;
			}
			this.counts = this.jdbc.queryForMap("""
					select (select count(*) from owners) as owners,
					       (select count(*) from pets) as pets,
					       (select count(*) from vets) as vets,
					       (select count(*) from visits) as visits
					""");
			this.available = true;
			log.atInfo()
				.addKeyValue("event.action", "business_snapshot")
				.addKeyValue("event.dataset", "petclinic.business")
				.addKeyValue("petclinic.owners", this.counts.get("owners"))
				.addKeyValue("petclinic.pets", this.counts.get("pets"))
				.addKeyValue("petclinic.vets", this.counts.get("vets"))
				.addKeyValue("petclinic.visits", this.counts.get("visits"))
				.log("Petclinic aggregate database snapshot");
		}
		catch (DataAccessException ex) {
			this.available = false;
			log.atWarn()
				.addKeyValue("event.action", "business_snapshot_failed")
				.log("Petclinic aggregate snapshot unavailable");
		}
	}

}
