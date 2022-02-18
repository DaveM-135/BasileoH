package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IClasificacionForecastDao;
import com.sophi.app.models.entity.ClasificacionForecast;

@Service
public class ClasificacionForecastServiceImpl implements IClasificacionForecastService {
	
	@Autowired
	private IClasificacionForecastDao clasificacionForecastDao;

	@Override
	@Transactional(readOnly = true)
	public List<ClasificacionForecast> findAll() {
		return (List<ClasificacionForecast>) clasificacionForecastDao.findAll();
	}

	@Override
	@Transactional(readOnly = true)
	public ClasificacionForecast findByCodClasificacion(Long codClasificacion) {
		return clasificacionForecastDao.findById(codClasificacion).orElse(null);
	}

	@Override
	@Transactional(readOnly = true)
	public List<String> findUniqueDescClasificacionPresupuesto() {
		return clasificacionForecastDao.findUniqueDescClasificacionPresupuesto();
	}

	@Override
	@Transactional(readOnly = true)
	public List<ClasificacionForecast> findByDescClasificacionPresupuesto(String descClasificacionPresupuesto) {
		return clasificacionForecastDao.findByDescClasificacionPresupuesto(descClasificacionPresupuesto);
	}

}
