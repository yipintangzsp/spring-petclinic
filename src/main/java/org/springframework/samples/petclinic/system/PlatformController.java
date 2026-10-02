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

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
class PlatformController {

	private final PlatformObservability platform;

	PlatformController(PlatformObservability platform) {
		this.platform = platform;
	}

	@GetMapping("/platform")
	String platform(Model model) {
		model.addAttribute("platform", this.platform.snapshot());
		return "platform";
	}

}
