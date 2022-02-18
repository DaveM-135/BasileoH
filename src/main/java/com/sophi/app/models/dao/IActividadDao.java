package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.Actividad;

public interface IActividadDao extends CrudRepository<Actividad, Long>{
	
	@Query("SELECT DISTINCT A.codProyecto FROM Actividad A WHERE A.codRecurso = ?1")
	List<Long> findListaProyectoByRecurso(Long codRecurso);
	
	@Query("SELECT DISTINCT A.descActividadPrimaria FROM Actividad A WHERE A.codRecurso = ?1 AND A.codProyecto = ?2")
	List<String> findListaActividadesPrimariasByRecursoProyecto(Long codRecurso, Long codProyecto);
	
	@Query("FROM Actividad A WHERE A.codRecurso = ?1 AND A.codProyecto = ?2")
	List<Actividad> findListaActividadesByRecursoProyecto(Long codRecurso, Long codProyecto);
	
	@Query("FROM Actividad A WHERE A.codRecurso = ?1 AND A.codProyecto = ?2 AND A.descActividadPrimaria = ?3 ")
	List<Actividad> findListaActividadesByRecursoProyectoPrimaria(Long codRecurso, Long codProyecto, String descPrimaria);

	List<Actividad> findByCodRecurso(Long codRecurso);
	
	long countByCodProyecto(Long codProyecto);
	
	List<Actividad> findByCodProyecto(Long codProyecto);
	
	@Query("SELECT SUM(A.valDuracionActividad) FROM Actividad A WHERE A.codRecurso = ?1 AND A.codProyecto = ?2")
	Float sumTotalHorasProyecto(Long codRecurso, Long codProyecto);
	
}
