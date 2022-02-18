package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.ISueldoDao;
import com.sophi.app.models.entity.Sueldo;

@Service
public class SueldoServiceImpl implements ISueldoService {
	
	@Autowired
	private ISueldoDao sueldoDao;

	@Override
	@Transactional(readOnly = true)
	public List<Sueldo> findAll() {
		return (List<Sueldo>) sueldoDao.findAll();
	}

	@Override
	@Transactional
	public void save(Sueldo sueldo) {
		sueldoDao.save(sueldo);
	}

	@Override
	@Transactional(readOnly = true)
	public Sueldo findOne(Long codSueldo) {
		return sueldoDao.findById(codSueldo).orElse(null);
	}

	@Override
	@Transactional
	public void delete(Sueldo sueldo) {
		sueldoDao.delete(sueldo);
	}

}
