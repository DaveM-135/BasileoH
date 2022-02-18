package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.Conocimientos;

public interface IConocimientoDao extends CrudRepository<Conocimientos, Long>{
	
	public List<Conocimientos> findByCodTipoConocimiento(Long codTipoConocimiento);

}
