package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.ContactoEmergencia;

public interface IContactoEmergenciaDao extends CrudRepository<ContactoEmergencia, Long>  {

	
	public List<ContactoEmergencia> findByCodRecurso(Long codRecurso);
}
