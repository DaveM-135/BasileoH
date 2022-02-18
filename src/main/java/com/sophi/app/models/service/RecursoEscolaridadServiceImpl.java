package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IRecursoEscolaridadDao;
import com.sophi.app.models.entity.RecursoEscolaridad;

@Service
public class RecursoEscolaridadServiceImpl implements IRecursoEscolaridadService {
	
	@Autowired
	private IRecursoEscolaridadDao recursoEscolaridadDao;

	@Override
	@Transactional(readOnly = true)
	public List<RecursoEscolaridad> findByCodRecurso(Long codRecurso) {
		return recursoEscolaridadDao.findByCodRecurso(codRecurso);
	}

	@Override
	@Transactional
	public void save(RecursoEscolaridad recursoEscolaridad) {
		recursoEscolaridadDao.save(recursoEscolaridad);
	}

	@Override
	@Transactional
	public void delete(Long codRecursoEscolaridad) {
		recursoEscolaridadDao.deleteById(codRecursoEscolaridad);
	}
	
	@Override
	@Transactional(readOnly = true)
	public RecursoEscolaridad findById(Long codRecursoEscolaridad) {
		return recursoEscolaridadDao.findById(codRecursoEscolaridad).orElse(null);
	}

}
