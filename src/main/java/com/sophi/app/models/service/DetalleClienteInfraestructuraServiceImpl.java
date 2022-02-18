package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IDetalleClienteInfraestructuraDao;
import com.sophi.app.models.entity.DetalleClienteInfraestructura;

@Service
public class DetalleClienteInfraestructuraServiceImpl implements IDetalleClienteInfraestructuraService {
	
	@Autowired
	private IDetalleClienteInfraestructuraDao detalleClienteInfraestructuraDao;

	@Override
	@Transactional(readOnly = true)
	public List<DetalleClienteInfraestructura> findAll() {
		return (List<DetalleClienteInfraestructura>) detalleClienteInfraestructuraDao.findAll();
	}

	@Override
	public void save(DetalleClienteInfraestructura contacto) {
		detalleClienteInfraestructuraDao.save(contacto);
	}


}
