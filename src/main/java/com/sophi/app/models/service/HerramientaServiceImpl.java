package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IHerramientaDao;
import com.sophi.app.models.entity.Herramienta;

@Service
public class HerramientaServiceImpl implements IHerramientaService {
	
	@Autowired
	private IHerramientaDao herramientaDao;

	@Override
	@Transactional(readOnly = true)
	public List<Herramienta> findAll() {
		return (List<Herramienta>) herramientaDao.findAll();
	}

	@Override
	@Transactional
	public void save(Herramienta herramienta) {
		herramientaDao.save(herramienta);
	}

	@Override
	@Transactional(readOnly = true)
	public Herramienta findOne(Long codHerramientaRecurso) {
		return herramientaDao.findById(codHerramientaRecurso).orElse(null);
	}
	
	@Override
	@Transactional(readOnly = true)
	public Herramienta findByCodHerramienta(Long codHerramienta) {
		return herramientaDao.findByCodHerramienta(codHerramienta);
	}
	
	@Override
	@Transactional(readOnly = true)
	public List<Herramienta> findByCodRecurso(Long codRecurso) {
		return herramientaDao.findByCodRecurso(codRecurso);
	}

	@Override
	@Transactional
	public void delete(Herramienta herramienta) {
		herramientaDao.delete(herramienta);
	}

}
