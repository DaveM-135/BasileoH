package com.sophi.app.models.dao;

import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.Competencias;

public interface ICompetenciasDao extends CrudRepository<Competencias, Long>{
	
	public Competencias findByDescCompetencias(String descCompetencia);

}
