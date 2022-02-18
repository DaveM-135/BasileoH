package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.ExpedienteDigital;

public interface IExpedienteDigitalService {
	
	public List<ExpedienteDigital> findByCodRecurso(Long codRecurso);
	
	public ExpedienteDigital findById(Long codExpedienteDigital);
	
	public void save(ExpedienteDigital expedienteDigital);
	
	public void delete(Long codExpedienteDigital);
	
	public ExpedienteDigital findByCodRecursoAndCodDocumento(Long codRecurso, Long codDocumento);
	
}
