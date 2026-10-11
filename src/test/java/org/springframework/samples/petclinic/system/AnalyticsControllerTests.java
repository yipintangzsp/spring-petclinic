/*
 * Copyright 2012-2026 the original author or authors.
 * Licensed under the Apache License, Version 2.0 (the "License").
 */
package org.springframework.samples.petclinic.system;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AnalyticsController.class)
class AnalyticsControllerTests {

	@Autowired
	private MockMvc mvc;

	@MockitoBean
	private ClinicAnalytics analytics;

	@BeforeEach
	void setUp() {
		var run = new ClinicAnalytics.Run("run-1", Instant.parse("2026-10-11T00:00:00Z"), LocalDate.parse("2026-01-01"),
				LocalDate.parse("2026-12-31"), "demo", 200, 350, 20, 1200);
		when(this.analytics.snapshot()).thenReturn(new ClinicAnalytics.Snapshot(run,
				List.of(new ClinicAnalytics.Day(LocalDate.parse("2026-10-01"), 7),
						new ClinicAnalytics.Day(LocalDate.parse("2026-10-02"), 9)),
				List.of(new ClinicAnalytics.Type("dog", 350)), true, false));
	}

	@Test
	void filterUsesInclusiveDatesAndKeepsDimensionCounts() throws Exception {
		this.mvc.perform(get("/insights").param("from", "2026-10-02").param("to", "2026-10-02"))
			.andExpect(status().isOk())
			.andExpect(model().attribute("visitCount", 9L))
			.andExpect(content().string(containsString("演示业务数据")))
			.andExpect(content().string(containsString("350")))
			.andExpect(content().string(containsString("2026-10-11T00:00:00Z")));
	}

	@Test
	void emptyRangeDoesNotInventCounts() throws Exception {
		this.mvc.perform(get("/insights").param("from", "2026-10-03").param("to", "2026-10-04"))
			.andExpect(status().isOk())
			.andExpect(model().attribute("visitCount", 0L))
			.andExpect(content().string(containsString("此日期范围暂无就诊记录")));
	}

	@Test
	void rejectReversedAndOversizedAndMalformedRanges() throws Exception {
		this.mvc.perform(get("/insights").param("from", "2026-10-04").param("to", "2026-10-03"))
			.andExpect(status().isBadRequest());
		this.mvc.perform(get("/insights").param("from", "2025-01-01").param("to", "2026-10-03"))
			.andExpect(status().isBadRequest());
		this.mvc.perform(get("/insights").param("from", "invalid")).andExpect(status().isBadRequest());
	}

	@Test
	void unavailableAnalysisKeepsNavigationUsable() throws Exception {
		when(this.analytics.snapshot())
			.thenReturn(new ClinicAnalytics.Snapshot(null, List.of(), List.of(), false, true));
		this.mvc.perform(get("/insights"))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("统计暂时不可用")))
			.andExpect(content().string(containsString("/pets")));
	}

	@Test
	void outOfCoverageIsExplicit() throws Exception {
		this.mvc.perform(get("/insights").param("from", "2025-12-30").param("to", "2026-01-02"))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("所选日期超出当前统计覆盖范围")));
	}

	@Test
	void staleSuccessIsDisplayedWithFailureNotice() throws Exception {
		var current = this.analytics.snapshot();
		when(this.analytics.snapshot())
			.thenReturn(new ClinicAnalytics.Snapshot(current.run(), current.days(), current.types(), true, true));
		this.mvc.perform(get("/insights").param("from", "2026-10-01").param("to", "2026-10-02"))
			.andExpect(status().isOk())
			.andExpect(model().attribute("visitCount", 16L))
			.andExpect(content().string(containsString("本次统计读取失败")));
	}

}
