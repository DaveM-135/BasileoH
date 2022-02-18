package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.Herramienta;

public interface IHerramientaDao extends CrudRepository<Herramienta, Long>{

	List<Herramienta> findByCodRecurso(Long codRecurso);
	
	Herramienta findByCodHerramienta(Long codHerramienta);
}
