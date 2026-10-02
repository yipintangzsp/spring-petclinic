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

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Properties;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.MeterBinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
class PlatformObservability implements MeterBinder {

	private static final Logger log = LoggerFactory.getLogger(PlatformObservability.class);

	private final Path path;

	private MeterRegistry registry;

	private Snapshot snapshot = new Snapshot(List.of(), 0, false);

	private long checked;

	private final Map<String, Double> jobCounts = new HashMap<>();

	PlatformObservability(
			@Value("${petclinic.platform.snapshot:/etc/petclinic-platform/snapshot.properties}") String path) {
		this.path = Path.of(path);
	}

	@Override
	public synchronized void bindTo(MeterRegistry registry) {
		this.registry = registry;
		Gauge.builder("petclinic.platform.snapshot.age", this, platform -> platform.snapshotAge())
			.baseUnit("seconds")
			.register(registry);
		snapshot();
	}

	synchronized double snapshotAge() {
		Snapshot current = snapshot();
		return current.updated() == 0 ? Double.NaN : Instant.now().getEpochSecond() - current.updated();
	}

	synchronized Snapshot snapshot() {
		long now = System.nanoTime();
		if (this.checked == 0 || now - this.checked > 30_000_000_000L) {
			this.checked = now;
			Properties values = new Properties();
			try (Reader reader = Files.newBufferedReader(this.path, StandardCharsets.UTF_8)) {
				values.load(reader);
				int count = Integer.parseInt(values.getProperty("count", "0"));
				long updated = Long.parseLong(values.getProperty("updated", "0"));
				List<Software> software = new ArrayList<>();
				for (int i = 0; i < Math.min(count, 200); i++) {
					String key = "item." + i + ".";
					Software item = new Software(values.getProperty(key + "id"), values.getProperty(key + "name"),
							values.getProperty(key + "namespace"),
							Integer.parseInt(values.getProperty(key + "desired")),
							Integer.parseInt(values.getProperty(key + "ready")),
							values.getProperty(key + "endpoint", ""),
							values.getProperty(key + "integration", "部署状态已同步"));
					software.add(item);
					if (this.registry != null) {
						for (String state : List.of("ready", "desired")) {
							Gauge
								.builder("petclinic.platform.workload", this,
										platform -> platform.value(item.id(), state))
								.tag("software", item.name())
								.tag("namespace", item.namespace())
								.tag("state", state)
								.register(this.registry);
						}
					}
				}
				this.snapshot = new Snapshot(List.copyOf(software), updated, true);
				log.atInfo()
					.addKeyValue("event.dataset", "petclinic.platform")
					.addKeyValue("event.action", "platform_snapshot")
					.addKeyValue("platform.total", software.size())
					.addKeyValue("platform.ready",
							software.stream().filter(s -> s.desired() > 0 && s.ready() >= s.desired()).count())
					.addKeyValue("platform.paused", software.stream().filter(s -> s.desired() == 0).count())
					.addKeyValue("platform.snapshot_timestamp", updated)
					.log("Petclinic platform inventory snapshot");
				values.stringPropertyNames().stream().filter(key -> key.startsWith("osint.")).forEach(key -> {
					String[] parts = key.split("\\.", 3);
					if (this.registry != null && parts.length == 3) {
						this.jobCounts.put(key, Double.parseDouble(values.getProperty(key)));
						Gauge.builder("petclinic.osint.jobs", this, platform -> platform.jobCount(key))
							.tag("tool", parts[1])
							.tag("status", parts[2])
							.register(this.registry);
					}
				});
			}
			catch (IOException | IllegalArgumentException ex) {
				this.snapshot = new Snapshot(this.snapshot.software(), this.snapshot.updated(), false);
			}
		}
		return this.snapshot;
	}

	private synchronized double jobCount(String key) {
		return snapshot().fresh() ? this.jobCounts.getOrDefault(key, Double.NaN) : Double.NaN;
	}

	private synchronized double value(String id, String state) {
		Snapshot current = snapshot();
		if (!current.fresh()) {
			return Double.NaN;
		}
		return current.software()
			.stream()
			.filter(s -> s.id().equals(id))
			.mapToDouble(s -> "ready".equals(state) ? s.ready() : s.desired())
			.findFirst()
			.orElse(Double.NaN);
	}

	public record Software(String id, String name, String namespace, int desired, int ready, String endpoint,
			String integration) {
		public String state() {
			return desired == 0 ? "已停用" : ready >= desired ? "副本就绪" : "副本不足";
		}
	}

	public record Snapshot(List<Software> software, long updated, boolean available) {
		public boolean fresh() {
			long age = Instant.now().getEpochSecond() - updated;
			return available && updated > 0 && age >= 0 && age < 180;
		}

		public String checkedAt() {
			return updated == 0 ? "未收到采集数据" : Instant.ofEpochSecond(updated).toString();
		}
	}

}
