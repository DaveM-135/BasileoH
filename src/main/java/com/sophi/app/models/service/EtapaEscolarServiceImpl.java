package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IEtapaEscolarDao;
import com.sophi.app.models.entity.EtapaEscolar;

@Service
public class EtapaEscolarServiceImpl implements IEtapaEscolarService {
	
	@Autowired
	private IEtapaEscolarDao etapaEscolarDao;

	@Override
	@Transactional(readOnly = true)
	public List<EtapaEscolar> findAll() {
		return (List<EtapaEscolar>) etapaEscolarDao.findAll();
	}
	

}
