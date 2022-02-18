package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IRespuestaCompetenciaDao;
import com.sophi.app.models.entity.RespuestaCompetencia;

@Service
public class RespuestaCompetenciaServiceImpl implements IRespuestaCompetenciaService{
	
	@Autowired
	private IRespuestaCompetenciaDao respuestaCompetenciaDao;

	@Override
	@Transactional
	public void guardar(RespuestaCompetencia respuestaCompetencia) {
		respuestaCompetenciaDao.save(respuestaCompetencia);
	}

	@Override
	@Transactional
	public void guardaAll(List<RespuestaCompetencia> respuestasCompetencia) {
		respuestaCompetenciaDao.saveAll(respuestasCompetencia);
	}

	@Override
	@Transactional(readOnly = true)
	public List<RespuestaCompetencia> findByRecursoEvaluacionTipo(Long codRecurso, Long codEvaluacion, Long tipo) {
		return respuestaCompetenciaDao.findByCodRecursoAndCodEvaluacionDesempenoAndValTipoEvaluadorOrderByCodCompetencias(codRecurso, codEvaluacion, tipo);
	}

	@Override
	@Transactional(readOnly = true)
	public RespuestaCompetencia findById(Long codRespuestaCompetencia) {
		return respuestaCompetenciaDao.findById(codRespuestaCompetencia).orElse(null);
	}

	@Override
	@Transactional(readOnly = true)
	public List<RespuestaCompetencia> findByCodRecursoAndCodEvaluacionDesempenoAndCodRecursoEvaluador(Long codRecurso,
			Long codEvaluacionDesempeno, Long codRecursoEvaluador) {
		return respuestaCompetenciaDao.findByCodRecursoAndCodEvaluacionDesempenoAndCodRecursoEvaluadorOrderByCodCompetencias(codRecurso, codEvaluacionDesempeno, codRecursoEvaluador);
	}

	@Override
	@Transactional(readOnly = true)
	public List<RespuestaCompetencia> findByRecursoEvaluacionTipoEvaluador(Long codRecurso, Long codEvaluacion,
			Long tipo, Long codRecursoEvaluador) {
		return respuestaCompetenciaDao.findByCodRecursoAndCodEvaluacionDesempenoAndValTipoEvaluadorAndCodRecursoEvaluadorOrderByCodCompetencias(codRecurso, codEvaluacion, tipo, codRecursoEvaluador);
	}

	@Override
	@Transactional(readOnly = true)
	public Long getTotalEvaluadosByCodRecursoAndCodEvaluacion(Long codRecurso, Long codEvaluacion) {
		return respuestaCompetenciaDao.getTotalEvaluadosByCodRecursoAndCodEvaluacion(codRecurso, codEvaluacion);
	}

	@Override
	@Transactional(readOnly = true)
	public List<RespuestaCompetencia> getRespuestasPromedioEvaluadores(Long codRecurso, Long codEvaluacion, Long tipo) {
		return respuestaCompetenciaDao.getRespuestasPromedioEvaluadores(codRecurso, codEvaluacion, tipo);
	}

}
