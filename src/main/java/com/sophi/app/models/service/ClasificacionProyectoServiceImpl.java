package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IClasificacionProyectoDao;
import com.sophi.app.models.entity.ClasificacionProyecto;

@Service
public class ClasificacionProyectoServiceImpl implements IClasificacionProyectoService {

	@Autowired
	private IClasificacionProyectoDao clasificacionProyectoDao;
	
	@Override
	@Transactional(readOnly = true)
	public List<ClasificacionProyecto> findAll() {
		return (List<ClasificacionProyecto>) clasificacionProyectoDao.findAll();
	}

	@Override
	@Transactional
	public void save(ClasificacionProyecto clasificacionProyecto) {
		clasificacionProyectoDao.save(clasificacionProyecto);
	}

	@Override
	@Transactional(readOnly = true)
	public ClasificacionProyecto findOne(Long odClasificacionProyecto) {
		return clasificacionProyectoDao.findById(odClasificacionProyecto).orElse(null);
	}

	
}
