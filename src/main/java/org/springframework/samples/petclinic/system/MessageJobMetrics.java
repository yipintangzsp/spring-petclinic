/*
 * Copyright 2012-2026 the original author or authors.
 * Licensed under the Apache License, Version 2.0 (the "License").
 */
package org.springframework.samples.petclinic.system;

import java.util.List;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.MeterBinder;
import org.springframework.stereotype.Component;

@Component
class MessageJobMetrics implements MeterBinder {

	private final MessageJobs jobs;

	MessageJobMetrics(MessageJobs jobs) {
		this.jobs = jobs;
	}

	@Override
	public void bindTo(MeterRegistry registry) {
		Gauge
			.builder("petclinic.messaging.storage.available", this.jobs, source -> source.metrics().available() ? 1 : 0)
			.register(registry);
		Gauge
			.builder("petclinic.messaging.outbox.pending", this.jobs,
					source -> source.metrics().available() ? source.metrics().pending() : Double.NaN)
			.register(registry);
		for (String state : List.of("queued", "running", "retrying", "success", "failed")) {
			Gauge
				.builder("petclinic.messaging.jobs", this.jobs, source -> source.metrics().available()
						? source.metrics().counts().getOrDefault(state, 0L) : Double.NaN)
				.tag("status", state)
				.register(registry);
		}
	}

}
