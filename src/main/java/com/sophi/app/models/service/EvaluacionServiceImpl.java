package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IEvaluacionDao;
import com.sophi.app.models.entity.Evaluacion;

@Service
public class EvaluacionServiceImpl implements IEvaluacionService {

	@Autowired
	private IEvaluacionDao evaluacionDao;
	
	@Override
	@Transactional(readOnly = true)
	public List<Evaluacion> listaEvaluacion() {
		return (List<Evaluacion>) evaluacionDao.findAll();
	}

}
