package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.Tarea;

public interface ITareaDao extends CrudRepository<Tarea, Long> {
	
	@Query("FROM Tarea T WHERE T.codTarea NOT IN (1,2)")
	List<Tarea> findTareaFueraPlan();

}
