package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IDetalleInfraestructuraDao;
import com.sophi.app.models.entity.DetalleInfraestructura;

@Service
public class DetalleInfraestructruraServiceImpl implements IDetalleInfraestructuraService {
	
	@Autowired
	private IDetalleInfraestructuraDao detalleInfraestructuraDao;

	@Override
	@Transactional(readOnly = true)
	public List<DetalleInfraestructura> findAll() {
		return (List<DetalleInfraestructura>) detalleInfraestructuraDao.findAll();
	}

	@Override
	public void save(DetalleInfraestructura detalleInfraestructura) {
		detalleInfraestructuraDao.save(detalleInfraestructura);
	}

	@Override
	@Transactional(readOnly = true)
	public DetalleInfraestructura findOne(Long codDetalleInfraestructura) {
		return detalleInfraestructuraDao.findById(codDetalleInfraestructura).orElse(null);
	}

}
