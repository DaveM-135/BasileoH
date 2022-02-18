package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IConocimientoDao;
import com.sophi.app.models.entity.Conocimientos;

@Service
public class ConocimietoServiceImpl implements IConocimientoService{
	
	@Autowired
	private IConocimientoDao conocimientoDao;
	

	@Override
	@Transactional(readOnly = true)
	public Conocimientos findById(Long codConocimiento) {
		return conocimientoDao.findById(codConocimiento).orElse(null);
	}

	@Override
	@Transactional(readOnly = true)
	public List<Conocimientos> findAll() {
		return (List<Conocimientos>) conocimientoDao.findAll();
	}

	@Override
	@Transactional(readOnly = true)
	public List<Conocimientos> findByCodTipoConocimiento(Long codTipoConocimiento) {
		return conocimientoDao.findByCodTipoConocimiento(codTipoConocimiento);
	}

}
