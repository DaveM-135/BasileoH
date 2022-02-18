package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.RecursoEscolaridad;

public interface IRecursoEscolaridadDao extends CrudRepository<RecursoEscolaridad, Long> {
	
	public List<RecursoEscolaridad> findByCodRecurso(Long codRecurso);
	

}
