package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IPreguntaClimaDao;
import com.sophi.app.models.entity.PreguntaClima;

@Service
public class PreguntaClimaServiceImpl implements IPreguntaClimaService {

	@Autowired
	private IPreguntaClimaDao preguntaClimaDao;
	
	@Override
	@Transactional(readOnly = true)
	public List<PreguntaClima> findAll() {
		return (List<PreguntaClima>) preguntaClimaDao.findAll();
	}

	@Override
	@Transactional(readOnly = true)
	public PreguntaClima findOne(Long codPreguntaClima) {
		return preguntaClimaDao.findById(codPreguntaClima).orElse(null);
	}

	@Override
	@Transactional
	public void save(PreguntaClima preguntaClima) {
		preguntaClimaDao.save(preguntaClima);
	}

	@Override
	@Transactional
	public void delete(Long codPreguntaClima) {
		preguntaClimaDao.deleteById(codPreguntaClima);
	}

}
