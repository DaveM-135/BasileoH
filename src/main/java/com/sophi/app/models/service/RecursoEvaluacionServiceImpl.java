package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IRecursoEvaluacionDao;
import com.sophi.app.models.entity.RecursoEvaluacion;

@Service
public class RecursoEvaluacionServiceImpl implements IRecursoEvaluacionService{

	@Autowired
	private IRecursoEvaluacionDao recursoEvaluacionDao;
	
	@Override
	@Transactional(readOnly = true)
	public List<RecursoEvaluacion> findByCodEvaluacionDesempeno(Long codEvaluacionDesempeno) {
		return recursoEvaluacionDao.findByCodEvaluacionDesempeno(codEvaluacionDesempeno);
	}

	@Override
	@Transactional(readOnly = true)
	public List<RecursoEvaluacion> findByCodRecurso(Long codRecurso) {
		return recursoEvaluacionDao.findByCodRecurso(codRecurso);
	}

	@Override
	@Transactional(readOnly = true)
	public RecursoEvaluacion findById(Long codRecursoEvaluacion) {
		return recursoEvaluacionDao.findById(codRecursoEvaluacion).orElse(null);
	}

	@Override
	@Transactional
	public void guardar(RecursoEvaluacion recursoEvaluacion) {
		recursoEvaluacionDao.save(recursoEvaluacion);
	}

	@Override
	@Transactional(readOnly = true)
	public RecursoEvaluacion findByCodRecursoAndCodEvaluacionDesempenoAndCodRecursoEvaluadorAndValTipoEvaluador(
			Long codRecurso, Long codEvaluacionDesempeno, Long codRecursoEvaluador, Long valTipoEvaluador) {
		return recursoEvaluacionDao.findByCodRecursoAndCodEvaluacionDesempenoAndCodRecursoEvaluadorAndValTipoEvaluador(codRecurso, codEvaluacionDesempeno, codRecursoEvaluador, valTipoEvaluador);
	}

	@Override
	@Transactional
	public void guardarAll(List<RecursoEvaluacion> recursosEvaluacion) {
		recursoEvaluacionDao.saveAll(recursosEvaluacion);
	}

	@Override
	@Transactional(readOnly = true)
	public List<RecursoEvaluacion> findByCodRecursoEvaluadorAndValTipoEvaluador(Long codRecursoEvaluador, Long valTipoEvaluador) {
		return recursoEvaluacionDao.findByCodRecursoEvaluadorAndValTipoEvaluador(codRecursoEvaluador, valTipoEvaluador);
	}

	@Override
	@Transactional(readOnly = true)
	public List<RecursoEvaluacion> findByCodRecursoAndValTipoEvaluador(Long codRecurso, Long valTipoEvaluador) {
		return recursoEvaluacionDao.findByCodRecursoAndValTipoEvaluador(codRecurso, valTipoEvaluador);
	}

	@Override
	@Transactional(readOnly = true)
	public List<RecursoEvaluacion> findByCodRecursoAndCodEvaluacionDesempeno(Long codRecurso, Long codEvaluacionDesempeno) {
		return recursoEvaluacionDao.findByCodRecursoAndCodEvaluacionDesempeno(codRecurso, codEvaluacionDesempeno);
	}

	@Override
	@Transactional(readOnly = true)
	public Float getPromedioCompetenciasByCodRecursoAndCodEvaluacion(Long codRecurso, Long codEvaluacion) {
		return recursoEvaluacionDao.getPromedioCompetenciasByCodRecursoAndCodEvaluacion(codRecurso, codEvaluacion);
	}

	@Override
	@Transactional(readOnly = true)
	public Float getPromedioCompetenciasByCodEvaluacion(Long codEvaluacion) {
		return recursoEvaluacionDao.getPromedioCompetenciasByCodEvaluacion(codEvaluacion);
	}

	@Override
	@Transactional(readOnly = true)
	public Float getPromedioCompetenciasByCodRecursoAndCodEvaluacionAndTipo(Long codRecurso,
			Long codEvaluacionDesempeno, Long tipo) {
		return recursoEvaluacionDao.getPromedioCompetenciasByCodRecursoAndCodEvaluacionAndTipo(codRecurso, codEvaluacionDesempeno, tipo);
	}

}
