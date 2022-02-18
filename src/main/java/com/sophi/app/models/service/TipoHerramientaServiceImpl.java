package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.ITipoHerramientaDao;
import com.sophi.app.models.entity.TipoHerramienta;

@Service
public class TipoHerramientaServiceImpl implements ITipoHerramientaService{
	
	@Autowired
	private ITipoHerramientaDao tipoHerramientaDao;

	@Override
	@Transactional(readOnly = true)
	public List<TipoHerramienta> findAll() {
		return (List<TipoHerramienta>) tipoHerramientaDao.findAll();
	}

}
