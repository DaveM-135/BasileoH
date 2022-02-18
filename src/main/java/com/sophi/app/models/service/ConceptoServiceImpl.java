package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.sophi.app.models.dao.IConceptoDao;
import com.sophi.app.models.entity.Concepto;

@Service
public class ConceptoServiceImpl implements IConceptoService{
	
	@Autowired
	private IConceptoDao conceptoDao;

	@Override
	public Concepto findByCodConcepto(Long codConcepto) {
		return conceptoDao.findById(codConcepto).orElse(null);
	}

	@Override
	public List<Concepto> findAll() {
		return (List<Concepto>) conceptoDao.findAll();
	}

}
