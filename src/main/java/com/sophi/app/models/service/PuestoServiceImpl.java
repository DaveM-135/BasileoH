package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IPuestoDao;
import com.sophi.app.models.entity.Puesto;

@Service
public class PuestoServiceImpl implements IPuestoService {
	
	@Autowired
	private IPuestoDao puestoDao;

	@Override
	@Transactional(readOnly = true)
	public List<Puesto> findAll() {
		return (List<Puesto>) puestoDao.findAll();
	}

	@Override
	@Transactional(readOnly = true)
	public Puesto findOne(Long codPuesto) {
		return puestoDao.findById(codPuesto).orElse(null);
	}

}
