package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IRecursoCapacitacionDao;
import com.sophi.app.models.entity.RecursoCapacitacion;

@Service
public class RecursoCapacitacionServiceImpl implements IRecursoCapacitacionService{
	
	@Autowired
	private IRecursoCapacitacionDao recursoCapacitacionDao;

	@Override
	@Transactional(readOnly = true)
	public List<RecursoCapacitacion> findByCodRecurso(Long codRecursoCapacitacion) {
		return recursoCapacitacionDao.findByCodRecurso(codRecursoCapacitacion);
	}

	@Override
	@Transactional
	public void save(RecursoCapacitacion recursoCapacitacion) {
		recursoCapacitacionDao.save(recursoCapacitacion);
	}

	@Override
	public void delete(Long codRecursoCapaciacion) {
		recursoCapacitacionDao.deleteById(codRecursoCapaciacion);
	}

	@Override
	@Transactional(readOnly = true)
	public RecursoCapacitacion findById(Long codRecursoCapacitacion) {
		return recursoCapacitacionDao.findById(codRecursoCapacitacion).orElse(null);
	}

	@Override
	@Transactional(readOnly = true)
	public Long countByCodCapacitacion(Long codCapacitacion) {
		return recursoCapacitacionDao.countByCodCapacitacion(codCapacitacion);
	}

}
