package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IAreaComercialDao;
import com.sophi.app.models.entity.AreaComercial;

@Service
public class AreaComercialServiceImpl implements IAreaComercialService {

	@Autowired
	private IAreaComercialDao areaComercialDao;
	
	@Override
	@Transactional(readOnly = true)
	public List<AreaComercial> findAll() {
		return (List<AreaComercial>) areaComercialDao.findAll();
	}

	@Override
	@Transactional
	public void save(AreaComercial areaComercial) {
		areaComercialDao.save(areaComercial);
	}

	@Override
	@Transactional(readOnly = true)
	public AreaComercial findOne(Long codAreaComercial) {
		return areaComercialDao.findById(codAreaComercial).orElse(null);
	}

	
}
