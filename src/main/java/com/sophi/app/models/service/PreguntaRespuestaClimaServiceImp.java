package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IPreguntaRespuestaClimaDao;
import com.sophi.app.models.entity.PreguntaRespuestaClima;

@Service
public class PreguntaRespuestaClimaServiceImp implements IPreguntaRespuestaClimaService {

	@Autowired
	private IPreguntaRespuestaClimaDao preguntaRespuestaClimaDao;
	
	@Override
	@Transactional(readOnly = true)
	public List<PreguntaRespuestaClima> findAll() {
		return (List<PreguntaRespuestaClima>) preguntaRespuestaClimaDao.findAll();
	}

	@Override
	@Transactional(readOnly = true)
	public PreguntaRespuestaClima findOne(Long codPreguntaRespuestaClima) {
		return preguntaRespuestaClimaDao.findById(codPreguntaRespuestaClima).orElse(null);
	}

	@Override
	@Transactional
	public void save(PreguntaRespuestaClima preguntaRespuestaClima) {
		preguntaRespuestaClimaDao.save(preguntaRespuestaClima);
	}

	@Override
	@Transactional
	public void delete(Long codPreguntaRespuestaClima) {
		preguntaRespuestaClimaDao.deleteById(codPreguntaRespuestaClima);
	}

	@Override
	@Transactional
	public List<PreguntaRespuestaClima> findByCodPregunta(Long codPregunta) {
		return preguntaRespuestaClimaDao.findByPreguntaClimaCodPreguntaClima(codPregunta);
	}
	

}
