package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.RecursoCapacitacion;

public interface IRecursoCapacitacionDao extends CrudRepository<RecursoCapacitacion, Long>{
	
	public List<RecursoCapacitacion> findByCodRecurso(Long codRecurso);
	
	@Query(value = "select count(cod_capacitacion) from RECURSOS_CAPACITACIONES where cod_capacitacion = ?1", nativeQuery = true)
	public Long countByCodCapacitacion(Long codCapacitacion);

}
