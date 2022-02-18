package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.ProyectoRecurso;
import com.sophi.app.models.entity.ProyectoRecursoId;

public interface IProyectoRecursoDao extends CrudRepository<ProyectoRecurso, ProyectoRecursoId>{
	
	List<ProyectoRecurso> findByProyectoRecursoIdCodRecurso(Long codRecurso);
	
	List<ProyectoRecurso> findByProyectoRecursoIdCodProyecto(Long codProyecto);
	
	@Query("FROM ProyectoRecurso PrR INNER JOIN Proyecto Pr ON PrR.proyectoRecursoId.codProyecto = Pr.codProyecto WHERE PrR.proyectoRecursoId.codRecurso = ?1 AND (Pr.codEstatusProyecto = 1 OR Pr.codEstatusProyecto = 2) ")
	List<ProyectoRecurso> findProyectoRecursoActivo(Long codRecurso);
	
}
