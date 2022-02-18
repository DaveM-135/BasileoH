package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.sophi.app.models.dao.IDocumentacionGeneralDao;
import com.sophi.app.models.entity.DocumentacionGeneral;

@Service
public class DocumentacionGeneralServiceImpl implements IDocumentacionGeneralService{
	
	@Autowired
	private IDocumentacionGeneralDao documentacionGeneralDao;

	@Override
	public List<DocumentacionGeneral> findAll() {
		return (List<DocumentacionGeneral>) documentacionGeneralDao.findAll();
	}

	@Override
	public DocumentacionGeneral findById(Long codDocumento) {
		return documentacionGeneralDao.findById(codDocumento).orElse(null);
	}

}
