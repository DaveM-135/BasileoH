package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IAprobacionHorasDao;
import com.sophi.app.models.entity.AprobacionHoras;

@Service
public class AprobacionHorasServicelmpl implements IAprobacionHorasService {

	@Autowired
	private IAprobacionHorasDao aprobacionhorasDao;

	@Override
	@Transactional(readOnly = true)
	public List<AprobacionHoras> findAll() {
		return (List<AprobacionHoras>) aprobacionhorasDao.findAll();
	}

	@Override
	public List<AprobacionHoras> findAprobacionHorasBycodProyecto(Long codProyecto) {
		return aprobacionhorasDao.findAprobacionHorasBycodProyecto(codProyecto);
	}
	
	@Override
	@Transactional(readOnly = true)
	public AprobacionHoras findOne(Long codActividad) {
		return aprobacionhorasDao.findById(codActividad).orElse(null);
	}

	@Override
	@Transactional
	public void saveAll(List<AprobacionHoras> aprobacionhoras) {
		aprobacionhorasDao.saveAll(aprobacionhoras);		
	}

	@Override
	@Transactional(readOnly = true)
	public List<AprobacionHoras> findAprobacionHorasGeneral(Long codProyecto) {
		return aprobacionhorasDao.findAprobacionHorasGeneral(codProyecto);
	}
	

}
