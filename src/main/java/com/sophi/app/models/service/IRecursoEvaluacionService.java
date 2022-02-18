package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.RecursoEvaluacion;

public interface IRecursoEvaluacionService {
	
	public List<RecursoEvaluacion> findByCodEvaluacionDesempeno(Long codEvaluacionDesempeno);
	
	public List<RecursoEvaluacion> findByCodRecurso(Long codRecurso);
	
	public List<RecursoEvaluacion> findByCodRecursoAndValTipoEvaluador(Long codRecurso, Long valTipoEvaluador);
	
	public RecursoEvaluacion findById(Long codRecursoEvaluacion);
	
	public void guardar(RecursoEvaluacion recursoEvaluacion);
	
	public void guardarAll(List<RecursoEvaluacion> recursosEvaluacion);
	
	public RecursoEvaluacion findByCodRecursoAndCodEvaluacionDesempenoAndCodRecursoEvaluadorAndValTipoEvaluador(Long codRecurso,Long codEvaluacionDesempeno,Long codRecursoEvaluador,Long valTipoEvaluador);

	public List<RecursoEvaluacion> findByCodRecursoEvaluadorAndValTipoEvaluador(Long codRecursoEvaluador, Long valTipoEvaluador);
	
	public List<RecursoEvaluacion> findByCodRecursoAndCodEvaluacionDesempeno(Long codRecurso,Long codEvaluacionDesempeno);
	
	public Float getPromedioCompetenciasByCodRecursoAndCodEvaluacion(Long codRecurso, Long codEvaluacion);
	
	public Float getPromedioCompetenciasByCodEvaluacion(Long codEvaluacion);
	
	public Float getPromedioCompetenciasByCodRecursoAndCodEvaluacionAndTipo(Long codRecurso,Long codEvaluacionDesempeno, Long tipo);
	
}
