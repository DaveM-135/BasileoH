package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IDetalleForecastDao;
import com.sophi.app.models.entity.DetalleForecast;
import com.sophi.app.models.entity.MesHabil;
import com.sophi.app.models.entity.Proyecto;
import com.sophi.app.models.entity.Recurso;

@Service
public class DetalleForecastServiceImpl implements IDetalleForecastService {
	
	@Autowired
	private IDetalleForecastDao detalleForecastDao;

	@Override
	@Transactional(readOnly = true)
	public List<DetalleForecast> findByRecurso(Recurso recurso) {
		return detalleForecastDao.findByRecurso(recurso);
	}

	@Override
	@Transactional(readOnly = true)
	public List<DetalleForecast> findByRecursoAndProyecto(Recurso recurso, Proyecto proyecto) {
		return detalleForecastDao.findByRecursoAndProyecto(recurso, proyecto);
	}

	@Override
	@Transactional
	public void save(DetalleForecast detalleForecast) {
		detalleForecastDao.save(detalleForecast);
	}

	@Override
	@Transactional
	public void delete(Long codDetalleForecast) {
		detalleForecastDao.deleteById(codDetalleForecast);
	}

	@Override
	@Transactional(readOnly = true)
	public List<DetalleForecast> findByRecursoAndMesHabil(Recurso recurso, MesHabil mesHabil) {
		return detalleForecastDao.findByRecursoAndMesHabil(recurso, mesHabil);
	}

	@Override
	@Transactional(readOnly = true)
	public DetalleForecast findById(Long codForecast) {
		return detalleForecastDao.findById(codForecast).orElse(null);
	}

}
