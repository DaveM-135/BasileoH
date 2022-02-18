package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.sophi.app.models.dao.IDependienteDao;
import com.sophi.app.models.entity.Dependiente;

@Service
public class DependienteServiceImpl implements IDependienteService {
	
	@Autowired
	private IDependienteDao dependienteDao;
	
	@Override
	public List<Dependiente> findAll() {
		return (List<Dependiente>) dependienteDao.findAll();
	}

	@Override
	public void save(Dependiente dependiente) {
		dependienteDao.save(dependiente);
	}

	@Override
	public Dependiente findOne(Long codDependiente) {
		return dependienteDao.findById(codDependiente).orElse(null);
	}

	@Override
	public void delete(Dependiente dependiente) {
		dependienteDao.delete(dependiente);
	}

}
