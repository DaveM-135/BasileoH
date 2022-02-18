package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IEstadoHerramientaDao;
import com.sophi.app.models.entity.EstadoHerramienta;

@Service
public class EstadoHerramientaServiceImpl implements IEstadoHerramientaService{
	
	@Autowired
	private IEstadoHerramientaDao estadoHerramientaDao;

	@Override
	@Transactional(readOnly = true)
	public List<EstadoHerramienta> findAll() {
		return (List<EstadoHerramienta>) estadoHerramientaDao.findAll();
	}

}
