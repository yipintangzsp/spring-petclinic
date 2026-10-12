/*
 * Copyright 2012-2026 the original author or authors.
 * Licensed under the Apache License, Version 2.0 (the "License").
 */
package org.springframework.samples.petclinic.system;

import org.springframework.stereotype.Component;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.MeterBinder;

@Component
class ClinicAnalysisMetrics implements MeterBinder {

	private final ClinicAnalytics analytics;

	ClinicAnalysisMetrics(ClinicAnalytics analytics) {
		this.analytics = analytics;
	}

	@Override
	public void bindTo(MeterRegistry registry) {
		Gauge.builder("petclinic.analysis.available", this, metrics -> metrics.analytics.snapshot().available() ? 1 : 0)
			.register(registry);
		Gauge.builder("petclinic.analysis.read.failed", this, metrics -> metrics.analytics.snapshot().failed() ? 1 : 0)
			.register(registry);
		Gauge.builder("petclinic.analysis.last.success.seconds", this, ClinicAnalysisMetrics::lastSuccess)
			.register(registry);
		Gauge.builder("petclinic.analysis.window.visits", this,
				metrics -> metrics.analytics.snapshot().days().stream().mapToLong(ClinicAnalytics.Day::visits).sum())
			.register(registry);
	}

	private double lastSuccess() {
		var run = this.analytics.snapshot().run();
		return run == null ? 0 : run.generatedAt().getEpochSecond();
	}

}
