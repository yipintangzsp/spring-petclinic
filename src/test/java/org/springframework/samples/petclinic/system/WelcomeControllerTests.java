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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.condition.DisabledInNativeImage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.aot.DisabledInAotMode;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import static org.mockito.Mockito.when;

@WebMvcTest(WelcomeController.class)
@DisabledInNativeImage
@DisabledInAotMode
class WelcomeControllerTests {

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private PetclinicDashboardService dashboardService;

	@BeforeEach
	void setUp() {
		var metrics = new PetclinicDashboardService.BusinessMetrics(10, 13, 6, true);
		var snapshot = new PetclinicDashboardService.DashboardSnapshot(metrics, "UP", "4.1.0", "Connected",
				"Local runtime", "test", "1", "abcdef0", "2026-09-10T00:00:00Z", "Local");
		when(this.dashboardService.snapshot()).thenReturn(snapshot);
	}

	@Test
	void welcome() throws Exception {
		mockMvc.perform(get("/")).andExpect(status().isOk()).andExpect(view().name("welcome"));
	}

	@Test
	void systemStatus() throws Exception {
		mockMvc.perform(get("/system-status")).andExpect(status().isOk()).andExpect(view().name("system-status"));
	}

}
