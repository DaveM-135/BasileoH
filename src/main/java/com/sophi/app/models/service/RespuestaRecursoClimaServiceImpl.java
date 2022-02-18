package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IRespuestaRecursoClimaDao;
import com.sophi.app.models.entity.Recurso;
import com.sophi.app.models.entity.RespuestaRecursoClima;

@Service
public class RespuestaRecursoClimaServiceImpl implements IRespuestaRecursoClimaService{

	@Autowired
	private IRespuestaRecursoClimaDao respuestaRecursoClimaDao;
	
	@Override
	@Transactional(readOnly = true)
	public List<RespuestaRecursoClima> findAll() {
		return (List<RespuestaRecursoClima>) respuestaRecursoClimaDao.findAll();
	}

	@Override
	@Transactional(readOnly = true)
	public RespuestaRecursoClima findOne(Long codRespuestaRecursoClima) {
		return respuestaRecursoClimaDao.findById(codRespuestaRecursoClima).orElse(null);
	}

	@Override
	@Transactional
	public void save(RespuestaRecursoClima respuestaRecursoClima) {
		respuestaRecursoClimaDao.save(respuestaRecursoClima);
	}

	@Override
	@Transactional
	public void delete(Long codRespuestaRecursoClima) {
		respuestaRecursoClimaDao.deleteById(codRespuestaRecursoClima);
	}

	@Override
	@Transactional(readOnly = true)
	public List<RespuestaRecursoClima> findByRecurso(Recurso recurso) {
		return respuestaRecursoClimaDao.findByRecurso(recurso);
	}

}
