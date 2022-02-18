package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IMetasPerfilesDao;
import com.sophi.app.models.entity.MetasPerfiles;

@Service
public class MetasPerfilServiceImpl implements IMetasPerfilesService {
	
	@Autowired
	private IMetasPerfilesDao metaPerfilDao;

	@Override
	@Transactional(readOnly = true)
	public void guardarAll(List<MetasPerfiles> metasPerfil) {
		metaPerfilDao.saveAll(metasPerfil);
	}

	@Override
	@Transactional
	public void deleteByCodPerfil(Long codPerfil) {
		metaPerfilDao.deleteByCodPerfil(codPerfil);
	}

	
	
}
