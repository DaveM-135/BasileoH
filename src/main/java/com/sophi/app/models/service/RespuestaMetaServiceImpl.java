package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IRespuestaMetaDao;
import com.sophi.app.models.dao.RespuestaMeta;

@Service
public class RespuestaMetaServiceImpl implements IRespuestaMetasService{
	
	@Autowired
	private IRespuestaMetaDao respuestaMetaDao;

	@Override
	@Transactional(readOnly = true)
	public List<RespuestaMeta> findByCodRecursoAndCodEvaluacionDesempeno(Long codRecurso, Long codEvaluacionDesempeno) {
		return respuestaMetaDao.findByCodRecursoAndCodEvaluacionDesempenoOrderByCodMeta(codRecurso, codEvaluacionDesempeno);
	}

	@Override
	@Transactional(readOnly = true)
	public RespuestaMeta findById(Long codRespuestaMeta) {
		return respuestaMetaDao.findById(codRespuestaMeta).orElse(null);
	}

	@Override
	@Transactional
	public void guardar(RespuestaMeta respuestaMeta) {
		respuestaMetaDao.save(respuestaMeta);
	}

	@Override
	@Transactional
	public void guardarAll(List<RespuestaMeta> listaRespuestasMetas) {
		respuestaMetaDao.saveAll(listaRespuestasMetas);
	}

	@Override
	@Transactional(readOnly = true)
	public Float getPromedioMetasByCodRecursoAndCodEvaluacion(Long codRecurso, Long codEvaluacion) {
		return respuestaMetaDao.getPromedioMetasByCodRecursoAndCodEvaluacion(codRecurso, codEvaluacion);
	}

	@Override
	@Transactional(readOnly = true)
	public Float getPromedioMetasByCodEvaluacion(Long codEvaluacion) {
		return respuestaMetaDao.getPromedioMetasByCodEvaluacion(codEvaluacion);
	}

}
