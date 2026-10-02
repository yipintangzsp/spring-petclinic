/*
 * Copyright 2012-2025 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.samples.petclinic.system;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.jdbc.core.JdbcTemplate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ObservabilityTests {

	@TempDir
	Path directory;

	@Test
	void businessGaugesExposeRealCountsAndDatabaseFailureIsNotZero() {
		JdbcTemplate jdbc = mock(JdbcTemplate.class);
		ObjectProvider<JdbcTemplate> provider = mock(ObjectProvider.class);
		when(provider.getIfAvailable()).thenReturn(jdbc);
		when(jdbc.queryForMap(org.mockito.ArgumentMatchers.anyString()))
			.thenReturn(Map.of("owners", 11L, "pets", 13L, "vets", 6L, "visits", 5L));
		{
			SimpleMeterRegistry registry = new SimpleMeterRegistry();
			new ClinicBusinessMetrics(provider).bindTo(registry);
			assertThat(registry.get("petclinic.business.records").tag("entity", "visits").gauge().value()).isEqualTo(5);
			assertThat(registry.get("petclinic.business.records").tag("entity", "owners").gauge().value())
				.isEqualTo(11);
			registry.close();
		}
		when(jdbc.queryForMap(org.mockito.ArgumentMatchers.anyString()))
			.thenThrow(new DataAccessResourceFailureException("database offline"));
		{
			SimpleMeterRegistry registry = new SimpleMeterRegistry();
			new ClinicBusinessMetrics(provider).bindTo(registry);
			assertThat(registry.get("petclinic.business.records").tag("entity", "owners").gauge().value()).isNaN();
			assertThat(registry.get("petclinic.business.database.available").gauge().value()).isZero();
			registry.close();
		}
	}

	@Test
	void absentAndStalePlatformDataAreNotReportedAsHealthy() throws Exception {
		PlatformObservability missing = new PlatformObservability(directory.resolve("absent").toString());
		assertThat(missing.snapshot().fresh()).isFalse();
		Path file = directory.resolve("stale");
		Files.writeString(file, "count=0\nupdated=" + (Instant.now().getEpochSecond() - 300) + "\n");
		assertThat(new PlatformObservability(file.toString()).snapshot().fresh()).isFalse();
	}

	@Test
	void platformMetricsRetainPausedComponentsAndOsintAggregates() throws Exception {
		Path file = directory.resolve("snapshot");
		Files.writeString(file, """
				count=1
				item.0.id=data-infra/minio
				item.0.name=minio
				item.0.namespace=data-infra
				item.0.desired=0
				item.0.ready=0
				osint.blackbird.succeeded=7
				updated=""" + Instant.now().getEpochSecond() + "\n");
		PlatformObservability platform = new PlatformObservability(file.toString());
		{
			SimpleMeterRegistry registry = new SimpleMeterRegistry();
			platform.bindTo(registry);
			assertThat(platform.snapshot().fresh()).isTrue();
			assertThat(platform.snapshot().software().get(0).state()).isEqualTo("已停用");
			assertThat(registry.get("petclinic.platform.workload").tag("state", "desired").gauge().value()).isZero();
			assertThat(registry.get("petclinic.osint.jobs")
				.tag("tool", "blackbird")
				.tag("status", "succeeded")
				.gauge()
				.value()).isEqualTo(7);
			registry.close();
		}
	}

}
