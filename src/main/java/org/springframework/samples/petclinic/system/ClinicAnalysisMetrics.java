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
		Gauge.builder("petclinic.analysis.available", this.analytics, source -> source.snapshot().available() ? 1 : 0)
			.strongReference(true)
			.register(registry);
		Gauge.builder("petclinic.analysis.read.failed", this.analytics, source -> source.snapshot().failed() ? 1 : 0)
			.strongReference(true)
			.register(registry);
		Gauge.builder("petclinic.analysis.last.success.seconds", this.analytics, ClinicAnalysisMetrics::lastSuccess)
			.strongReference(true)
			.register(registry);
		Gauge.builder("petclinic.analysis.window.visits", this.analytics, ClinicAnalysisMetrics::windowVisits)
			.strongReference(true)
			.register(registry);
	}

	private static double windowVisits(ClinicAnalytics analytics) {
		var snapshot = analytics.snapshot();
		return snapshot.available() ? snapshot.days().stream().mapToLong(ClinicAnalytics.Day::visits).sum()
				: Double.NaN;
	}

	private static double lastSuccess(ClinicAnalytics analytics) {
		var run = analytics.snapshot().run();
		return run == null ? 0 : run.generatedAt().getEpochSecond();
	}

}
