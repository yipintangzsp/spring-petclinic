package org.springframework.samples.petclinic.owner;

import java.time.LocalDate;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.hamcrest.Matchers.containsString;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class ClinicWorkflowIntegrationTests {

	@Autowired
	MockMvc mvc;

	@Autowired
	OwnerRepository owners;

	@Autowired
	jakarta.persistence.EntityManager entityManager;

	@Test
	@org.springframework.transaction.annotation.Transactional(
			propagation = org.springframework.transaction.annotation.Propagation.NOT_SUPPORTED)
	void fullDirectoryRendersOutsidePersistenceSession() throws Exception {
		mvc.perform(get("/pets")).andExpect(status().isOk()).andExpect(content().string(containsString("Betty Davis")));
	}

	@Test
	void directoriesFilterAndRenderRealRecords() throws Exception {
		mvc.perform(get("/owners").param("q", "George").param("city", "Madison"))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("George Franklin")));
		mvc.perform(get("/owners").param("q", "no-match"))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("No owners found")));
		mvc.perform(get("/pets").param("q", "Leo").param("type", "cat"))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("Open care record")));
		mvc.perform(get("/pets").param("q", "no-match"))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("No pets found")));
		mvc.perform(get("/vets.html").param("specialty", "radiology"))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("Helen Leary")));
		mvc.perform(get("/vets.html").param("specialty", "no-match"))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("No veterinarians found")));
		mvc.perform(get("/owners").param("page", "-1").param("sort", "invalid")).andExpect(status().isOk());
		mvc.perform(get("/owners/1/pets/99999")).andExpect(status().isNotFound());
		mvc.perform(get("/pets").param("page", "999")).andExpect(status().isOk());
	}

	@Test
	void visitSubmissionIsReadBackFromDatabase() throws Exception {
		int before = owners.findById(1).orElseThrow().getPet(1).getVisits().size();
		mvc.perform(post("/owners/1/pets/1/visits/new").param("date", LocalDate.now().plusDays(2).toString())
			.param("description", "Integration follow-up"))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/owners/1/pets/1"));
		entityManager.flush();
		entityManager.clear();
		var history = owners.findById(1).orElseThrow().getPet(1).getVisitHistory();
		assertThat(history).hasSize(before + 1);
		assertThat(history.get(0).getDescription()).isEqualTo("Integration follow-up");
		mvc.perform(get("/owners/1/pets/1"))
			.andExpect(status().isOk())
			.andExpect(content().string(containsString("Integration follow-up")));
	}

	@Test
	void viewingFormDoesNotAddPhantomVisits() throws Exception {
		var pet = owners.findById(1).orElseThrow().getPet(1);
		int before = pet.getVisits().size();
		mvc.perform(get("/owners/1/pets/1/visits/new")).andExpect(status().isOk());
		assertThat(pet.getVisits()).hasSize(before);
		mvc.perform(post("/owners/1/pets/1/visits/new").param("date", "").param("description", " "))
			.andExpect(status().isOk())
			.andExpect(model().attributeHasFieldErrors("visit", "date", "description"));
		assertThat(pet.getVisits()).hasSize(before);
	}

}
