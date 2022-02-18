package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.ISolicitudVacacionesDao;
import com.sophi.app.models.entity.SolicitudVacaciones;

@Service
public class SolicitudVacacionesServiceImpl implements ISolicitudVacacionesService {
	
	@Autowired
	private ISolicitudVacacionesDao solicitudVacacionesDao;

	@Override
	@Transactional(readOnly = true)
	public SolicitudVacaciones findById(Long codSolicitudVacaciones) {
		return solicitudVacacionesDao.findById(codSolicitudVacaciones).orElse(null);
	}

	@Override
	@Transactional(readOnly = true)
	public List<SolicitudVacaciones> findByCodRecurso(Long codRecurso) {
		return solicitudVacacionesDao.findByCodRecurso(codRecurso);
	}

	@Override
	@Transactional
	public void save(SolicitudVacaciones solicitud) {
		solicitudVacacionesDao.save(solicitud);
	}

	@Override
	@Transactional
	public void delete(SolicitudVacaciones solicitud) {
		solicitudVacacionesDao.delete(solicitud);
	}

}
