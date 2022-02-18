package com.sophi.app.models.service;

import java.util.List;


import com.sophi.app.models.dao.RespuestaMeta;

public interface IRespuestaMetasService {
	
	public List<RespuestaMeta> findByCodRecursoAndCodEvaluacionDesempeno(Long codRecurso, Long codEvaluacionDesempeno);
	
	public RespuestaMeta findById(Long codRespuestaMeta);
	
	public void guardar(RespuestaMeta respuestaMeta);
	
	public void guardarAll(List<RespuestaMeta> listaRespuestasMetas); 
	
	public Float getPromedioMetasByCodRecursoAndCodEvaluacion(Long codRecurso, Long codEvaluacion);
	
	public Float getPromedioMetasByCodEvaluacion(Long codEvaluacion);

}
