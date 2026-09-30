package org.springframework.samples.petclinic.owner;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface PetRepository extends JpaRepository<Pet, Integer> {

	@org.springframework.data.jpa.repository.EntityGraph(attributePaths = { "owner", "type" })
	@Query("""
			select p from Pet p join p.owner o where
			(:q = '' or lower(p.name) like lower(concat('%', :q, '%'))
			or lower(concat(o.firstName, ' ', o.lastName)) like lower(concat('%', :q, '%')))
			and (:type = '' or p.type.name = :type)
			""")
	Page<Pet> search(String q, String type, Pageable pageable);

}
