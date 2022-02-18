package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.Subtarea;

public interface ISubtareaDao extends CrudRepository<Subtarea, Long>{
	
	@Query("FROM Subtarea S WHERE S.tarea.codTarea NOT IN (1,2)")
	List<Subtarea> findFueraPlan();
	
	List<Subtarea> findByTareaCodTarea(Long codTarea);
	

}
