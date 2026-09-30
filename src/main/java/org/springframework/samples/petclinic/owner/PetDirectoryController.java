package org.springframework.samples.petclinic.owner;

import java.util.List;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
class PetDirectoryController {

	private final PetRepository pets;

	private final PetTypeRepository types;

	PetDirectoryController(PetRepository pets, PetTypeRepository types) {
		this.pets = pets;
		this.types = types;
	}

	@GetMapping("/pets")
	String list(@RequestParam(defaultValue = "") String q, @RequestParam(defaultValue = "") String type,
			@RequestParam(defaultValue = "name") String sort, @RequestParam(defaultValue = "1") int page, Model model) {
		sort = List.of("name", "birthDate").contains(sort) ? sort : "name";
		page = Math.max(1, page);
		var ordering = Sort.by(sort).ascending().and(Sort.by("id"));
		var results = pets.search(q.strip(), type, PageRequest.of(page - 1, 6, ordering));
		if (page > Math.max(1, results.getTotalPages())) {
			page = Math.max(1, results.getTotalPages());
			results = pets.search(q.strip(), type, PageRequest.of(page - 1, 6, ordering));
		}
		model.addAttribute("listPets", results.getContent());
		model.addAttribute("totalItems", results.getTotalElements());
		model.addAttribute("totalPages", results.getTotalPages());
		model.addAttribute("currentPage", page);
		model.addAttribute("q", q.strip());
		model.addAttribute("type", type);
		model.addAttribute("sort", sort);
		model.addAttribute("types", types.findPetTypes());
		return "pets/petsList";
	}

}
