package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.Concepto;

public interface IConceptoService {

	public Concepto findByCodConcepto(Long codConcepto);
	
	public List<Concepto> findAll();
	
}
