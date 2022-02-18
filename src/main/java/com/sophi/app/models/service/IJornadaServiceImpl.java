package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IJornadaDao;
import com.sophi.app.models.entity.Jornada;

@Service
public class IJornadaServiceImpl implements IJornadaService {

	@Autowired
	private IJornadaDao jornadaDao;
	
	@Override
	@Transactional(readOnly = true)
	public List<Jornada> findAll() {
		return (List<Jornada>) jornadaDao.findAll();
	}

	@Override
	@Transactional(readOnly = true)
	public Jornada findOne(Long codJornada) {
		return jornadaDao.findById(codJornada).orElse(null);
	}

}
