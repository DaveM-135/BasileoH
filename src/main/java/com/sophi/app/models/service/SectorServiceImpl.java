package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.ISectorDao;
import com.sophi.app.models.entity.Sector;

@Service
public class SectorServiceImpl implements ISectorService {
	
	@Autowired
	private ISectorDao sectorDao;

	@Override
	@Transactional(readOnly = true)
	public List<Sector> findAll() {
		return (List<Sector>) sectorDao.findAll();
	}

	@Override
	@Transactional
	public void save(Sector sector) {
		sectorDao.save(sector);
	}

	@Override
	@Transactional(readOnly = true) 
	public Sector findOne(Long codSector) {
		return sectorDao.findById(codSector).orElse(null);
	}

}
