package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.ITipoFacturacionDao;
import com.sophi.app.models.entity.TipoFacturacion;

@Service
public class TipoFacturacionServiceImpl implements ITipoFacturacionService {

	@Autowired
	private ITipoFacturacionDao tipoFacturacionDao;
	
	@Override
	@Transactional(readOnly = true)
	public List<TipoFacturacion> findAll() {
		return (List<TipoFacturacion>) tipoFacturacionDao.findAll();
	}

	@Override
	@Transactional
	public void save(TipoFacturacion tipoFacturacion) {
		tipoFacturacionDao.save(tipoFacturacion);
	}

	@Override
	@Transactional(readOnly = true)
	public TipoFacturacion findOne(Long tipoFacturacion) {
		return tipoFacturacionDao.findById(tipoFacturacion).orElse(null);
	}

	
}
