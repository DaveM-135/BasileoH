package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.RecursoGasto;

public interface IRecursoGastoDao extends CrudRepository<RecursoGasto, Long>{
	
	List<RecursoGasto> findByCodRecurso(Long codRecurso);
	
}
