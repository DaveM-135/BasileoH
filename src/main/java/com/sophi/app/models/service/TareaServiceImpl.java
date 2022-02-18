package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.ITareaDao;
import com.sophi.app.models.entity.Tarea;

@Service
public class TareaServiceImpl implements ITareaService {
	
	@Autowired
	private ITareaDao tareaDao;

	@Override
	@Transactional(readOnly = true)
	public List<Tarea> findAll() {
		return (List<Tarea>) tareaDao.findAll();
	}

	@Override
	@Transactional(readOnly = true)
	public Tarea findOne(Long codTarea) {
		return tareaDao.findById(codTarea).orElse(null);
	}

	@Override
	@Transactional(readOnly = true)
	public List<Tarea> findTareaFueraPlan() {
		return tareaDao.findTareaFueraPlan();
	}

}
