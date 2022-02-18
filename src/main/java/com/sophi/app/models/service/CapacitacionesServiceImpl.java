package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.ICapacitacionDao;
import com.sophi.app.models.entity.Capacitaciones;

@Service
public class CapacitacionesServiceImpl implements ICapacitacionesService{
	
	@Autowired
	private ICapacitacionDao capacitacionDao;

	@Override
	@Transactional(readOnly = true)
	public Capacitaciones findById(Long codCapacitacion) {
		return capacitacionDao.findById(codCapacitacion).orElse(null);
	}

	@Override
	@Transactional
	public void save(Capacitaciones capacitacion) {
		capacitacionDao.save(capacitacion);
	}

	@Override
	@Transactional
	public void delete(Long codCapacitacion) {
		capacitacionDao.deleteById(codCapacitacion);
	}

	@Override
	@Transactional(readOnly = true)
	public List<Capacitaciones> findAll() {
		return (List<Capacitaciones>) capacitacionDao.findAll();
	}

}
