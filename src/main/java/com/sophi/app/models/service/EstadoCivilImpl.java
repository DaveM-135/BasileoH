package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IEstadoCivilDao;
import com.sophi.app.models.entity.EstadoCivil;

@Service
public class EstadoCivilImpl implements IEstadoCivilService {

	@Autowired
	private IEstadoCivilDao estadoCivilDao;
	
	@Override
	@Transactional(readOnly = true)
	public List<EstadoCivil> findAll(){
		return (List<EstadoCivil>) estadoCivilDao.findAll();
	}

}
