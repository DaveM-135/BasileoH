package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IEtapaDao;
import com.sophi.app.models.entity.Etapa;

@Service
public class EtapaServiceImpl implements IEtapaService {

	@Autowired
	private IEtapaDao etapaDao;
	
	@Override
	@Transactional(readOnly = true)
	public Etapa findByCodEtapa(Long codEtapa) {
		return etapaDao.findById(codEtapa).orElse(null);
	}

	@Override
	@Transactional(readOnly = true)
	public List<Etapa> findAll() {
		return (List<Etapa>) etapaDao.findAll();
	}
					
}
