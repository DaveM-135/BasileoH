package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.SolicitudVacaciones;

public interface ISolicitudVacacionesDao extends CrudRepository<SolicitudVacaciones, Long>{
	
	public List<SolicitudVacaciones> findByCodRecurso(Long codRecurso);

}
