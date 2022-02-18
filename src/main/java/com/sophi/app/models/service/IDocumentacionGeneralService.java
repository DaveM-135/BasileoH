package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.DocumentacionGeneral;

public interface IDocumentacionGeneralService {
	
	public List<DocumentacionGeneral> findAll();
	
	public DocumentacionGeneral findById(Long codDocumento);

}
