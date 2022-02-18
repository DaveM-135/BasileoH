package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.ExpedienteDigital;

public interface IExpedienteDigitalDao extends CrudRepository<ExpedienteDigital, Long>{

	public List<ExpedienteDigital> findByCodRecurso(Long codRecurso);
	
	public ExpedienteDigital findByCodRecursoAndCodDocumento(Long codRecurso, Long codDocumento);
	
	
	
}
