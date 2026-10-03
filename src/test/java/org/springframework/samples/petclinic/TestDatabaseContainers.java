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

package org.springframework.samples.petclinic;

import org.testcontainers.mysql.MySQLContainer;
import org.testcontainers.utility.DockerImageName;

/** Database fixtures share the Docker host with the running platform. */
final class TestDatabaseContainers {

	private static final long MYSQL_MEMORY_BYTES = 512L * 1024 * 1024;

	private TestDatabaseContainers() {
	}

	static MySQLContainer mysql() {
		return new MySQLContainer(DockerImageName.parse("mysql:9.7"))
			.withCommand("--performance-schema=OFF", "--innodb-buffer-pool-size=64M", "--max-connections=30")
			.withCreateContainerCmdModifier(cmd -> cmd.getHostConfig()
				.withMemory(MYSQL_MEMORY_BYTES)
				.withMemorySwap(MYSQL_MEMORY_BYTES)
				.withOomScoreAdj(1000));
	}

}
