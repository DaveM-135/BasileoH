package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IExperienciaDao;
import com.sophi.app.models.entity.Experiencia;

@Service
public class ExperienciaServiceImpl implements IExperienciaService{
	
	@Autowired
	private IExperienciaDao experienciaDao;

	@Override
	@Transactional(readOnly = true)
	public List<Experiencia> findAll() {
		return (List<Experiencia>) experienciaDao.findAll();
	}

	
	
}
