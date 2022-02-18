package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.ISubtareaDao;
import com.sophi.app.models.entity.Subtarea;

@Service
public class SubtareaServiceImpl implements ISubtareaService {
	
	@Autowired
	private ISubtareaDao subtareaDao;

	@Override
	@Transactional(readOnly = true)
	public List<Subtarea> findAll() {
		return (List<Subtarea>) subtareaDao.findAll();
	}

	@Override
	@Transactional(readOnly = true)
	public Subtarea findOne(Long codSubtarea) {
		return subtareaDao.findById(codSubtarea).orElse(null);
	}

	@Override
	@Transactional(readOnly = true)
	public List<Subtarea> findByCodTarea(Long codTarea) {
		return subtareaDao.findByTareaCodTarea(codTarea);
	}

	@Override
	@Transactional(readOnly = true)
	public List<Subtarea> findFueraDePlan() {
		return subtareaDao.findFueraPlan();
	}

}
