package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.RespuestaCompetencia;

public interface IRespuestaCompetenciaService {
	
	public void guardar(RespuestaCompetencia respuestaCompetencia);
	
	public void guardaAll(List<RespuestaCompetencia> respuestasCompetencia);
	
	public List<RespuestaCompetencia> findByRecursoEvaluacionTipo(Long codRecurso, Long codEvaluacion, Long tipo);
	
	public List<RespuestaCompetencia> findByRecursoEvaluacionTipoEvaluador(Long codRecurso, Long codEvaluacion, Long tipo, Long codRecursoEvaluador); 
	
	public RespuestaCompetencia findById(Long codRespuestaCompetencia);
	
	public List<RespuestaCompetencia> findByCodRecursoAndCodEvaluacionDesempenoAndCodRecursoEvaluador(Long codRecurso, Long codEvaluacionDesempeno, Long codRecursoEvaluador);
	
	public Long getTotalEvaluadosByCodRecursoAndCodEvaluacion(Long codRecurso, Long codEvaluacion);
	
	public List<RespuestaCompetencia> getRespuestasPromedioEvaluadores(Long codRecurso, Long codEvaluacion, Long tipo);
	
}
