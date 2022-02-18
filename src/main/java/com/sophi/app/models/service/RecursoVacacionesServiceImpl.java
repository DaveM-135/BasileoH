package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IRecursoVacacionesDao;
import com.sophi.app.models.entity.RecursoVacaciones;

@Service
public class RecursoVacacionesServiceImpl implements IRecursoVacacionesService{
	
	@Autowired
	private IRecursoVacacionesDao recursoVacacionesDao;

	@Override
	@Transactional(readOnly = true)
	public RecursoVacaciones findById(Long codRecursoVacaciones) {
		return recursoVacacionesDao.findById(codRecursoVacaciones).orElse(null);
	}

	@Override
	@Transactional(readOnly = true)
	public List<RecursoVacaciones> findAll() {
		return (List<RecursoVacaciones>) recursoVacacionesDao.findAll();
	}

	@Override
	@Transactional
	public void save(RecursoVacaciones recursoVacaciones) {
		recursoVacacionesDao.save(recursoVacaciones);
	}
	

}
