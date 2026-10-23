/*
 * Copyright 2012-2026 the original author or authors.
 * Licensed under the Apache License, Version 2.0 (the "License").
 */
package org.springframework.samples.petclinic.system;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;

@WebMvcTest(MessageJobsController.class)
class MessageJobsControllerTests {

	@Autowired
	private MockMvc mvc;

	@MockitoBean
	private MessageJobs jobs;

	@Test
	void unavailableTaskPageExplainsRealState() throws Exception {
		when(this.jobs.snapshot())
			.thenReturn(new MessageJobs.Snapshot(false, List.of(), List.of(), List.of(), Map.of()));
		this.mvc.perform(get("/jobs").param("lang", "zh"))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("任务存储暂不可用")));
	}

	@Test
	void statusAndResultAreVisibleWithoutInventingSuccess() throws Exception {
		var job = new MessageJobs.Job("report-1", "statistics_report", "failed", 3, 3, 4, 4, "2026-10-23T00:00:00Z",
				null, "ValueError");
		when(this.jobs.snapshot()).thenReturn(new MessageJobs.Snapshot(true, List.of(job),
				List.of(Map.of("event_id", "visit-1", "visit_id", 1, "owner_id", 1, "pet_id", 1, "status", "todo")),
				List.of(Map.of("release", "0.10.0-ci-test", "build", 1, "source_commit", "abcdef", "received_at",
						"2026-10-23")),
				Map.of("failed", 1L)));
		this.mvc.perform(get("/jobs").param("lang", "zh"))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("ValueError")))
			.andExpect(content().string(containsString("重新处理")))
			.andExpect(content().string(containsString("标记完成")))
			.andExpect(content().string(containsString("0.10.0-ci-test")));
		when(this.jobs.job("report-1")).thenReturn(job);
		this.mvc.perform(get("/api/messaging/jobs/report-1"))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("failed")));
	}

	@Test
	void createsReportAndPreservesPostRedirectGet() throws Exception {
		when(this.jobs.report("request-key", LocalDate.parse("2026-01-01"), LocalDate.parse("2026-12-31")))
			.thenReturn("report-1");
		when(this.jobs.job("report-1"))
			.thenReturn(new MessageJobs.Job("report-1", "statistics_report", "queued", 0, 0, 1, 0, "now", null, null));
		this.mvc.perform(
				post("/jobs/reports").param("key", "request-key").param("from", "2026-01-01").param("to", "2026-12-31"))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/jobs"));
		this.mvc
			.perform(post("/api/messaging/reports").param("key", "request-key")
				.param("from", "2026-01-01")
				.param("to", "2026-12-31"))
			.andExpect(status().isAccepted())
			.andExpect(content().string(containsString("queued")));
		this.mvc.perform(
				post("/jobs/reports").param("key", "request-key").param("from", "invalid").param("to", "2026-12-31"))
			.andExpect(status().isBadRequest());
	}

	@Test
	void retryAndCompletionRequirePost() throws Exception {
		this.mvc.perform(post("/jobs/report-1/retry")).andExpect(status().is3xxRedirection());
		verify(this.jobs).retry("report-1");
		this.mvc.perform(post("/jobs/followups/visit-1/complete")).andExpect(status().is3xxRedirection());
		verify(this.jobs).completeFollowup("visit-1");
		this.mvc.perform(get("/jobs/report-1/retry")).andExpect(status().isMethodNotAllowed());
	}

}
