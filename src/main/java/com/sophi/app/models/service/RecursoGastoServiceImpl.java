package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IRecursoGastoDao;
import com.sophi.app.models.entity.RecursoGasto;

@Service
public class RecursoGastoServiceImpl implements IRecursoGastoService {
	
	@Autowired
	private IRecursoGastoDao recursoGastoDao;

	@Override
	@Transactional(readOnly = true)
	public List<RecursoGasto> findAll() {
		return (List<RecursoGasto>) recursoGastoDao.findAll();
	}

	@Override
	@Transactional
	public void save(RecursoGasto recursoGasto) {
		recursoGastoDao.save(recursoGasto);
	}

	@Override
	@Transactional(readOnly = true)
	public RecursoGasto findOne(Long recursoGastoId) {
		return recursoGastoDao.findById(recursoGastoId).orElse(null);
	}

	@Override
	@Transactional
	public void delete(RecursoGasto recursoGasto) {
		recursoGastoDao.delete(recursoGasto);
	}
	
	@Override
	@Transactional(readOnly = true)
	public List<RecursoGasto> findByCodRecurso(Long codRecurso) {
		return (List<RecursoGasto>) recursoGastoDao.findByCodRecurso(codRecurso);
	}
	
}
