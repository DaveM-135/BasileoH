package com.sophi.app.models.service;

import java.util.Date;
import java.util.List;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IEvaluacionDesempenoDao;
import com.sophi.app.models.entity.EvaluacionDesempeno;

@Service
public class EvaluacionDesempenoServiceImpl implements IEvaluacionDesempenoService{
	
	@Autowired
	private IEvaluacionDesempenoDao evaluacionDesempenoDao;

	@Override
	@Transactional(readOnly = true)
	public List<EvaluacionDesempeno> findAll() {
		return (List<EvaluacionDesempeno>) evaluacionDesempenoDao.findAll();
	}

	@Override
	@Transactional(readOnly = true)
	public EvaluacionDesempeno findById(Long codEvaluacionDesempeno) {
		return evaluacionDesempenoDao.findById(codEvaluacionDesempeno).orElse(null);
	}

	@Override
	@Transactional
	public void guardar(EvaluacionDesempeno evaluacionDesempeno) {
		evaluacionDesempenoDao.save(evaluacionDesempeno);
	}

	@Override
	@Transactional
	public void delete(Long codEvaluacionDesempeno) {
		evaluacionDesempenoDao.deleteById(codEvaluacionDesempeno);
	}

	@Override
	@Transactional
	public void updateCierreEvaluacionDesempeno(Long codEvaluacionDesempeno, Long valEstatus, Date fecCierre, Float promedioEmpresa) {
		evaluacionDesempenoDao.updateCierreEvaluacionDesempeno(codEvaluacionDesempeno, valEstatus, fecCierre, promedioEmpresa);
	}

	@Override
	@Transactional(readOnly = true)
	public Float getHorasHabilesByMes(Long mesIdInicio, Long mesIdFin) {
		return evaluacionDesempenoDao.getHorasHabilesByMes(mesIdInicio, mesIdFin);
	}

	@Override
	@Transactional(readOnly = true)
	public Float getHorasHabilesValidadasByCodRecursoAndMes(Long codRecurso, Date fecInicio, Date fecFin) {
		return evaluacionDesempenoDao.getHorasHabilesValidadasByCodRecursoAndMes(codRecurso, fecInicio, fecFin);
	}

	@Override
	@Transactional(readOnly = true)
	public Float getAvgCsiByCodRecursoAndMes(Long codRecurso, Date fecInicio, Date fecFin) {
		return evaluacionDesempenoDao.getAvgCsiByCodRecursoAndMes(codRecurso, fecInicio, fecFin);
	}

}
