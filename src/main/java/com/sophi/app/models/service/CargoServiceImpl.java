package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.ICargoDao;
import com.sophi.app.models.entity.Cargo;

@Service
public class CargoServiceImpl implements ICargoService{
	
	@Autowired
	private ICargoDao cargoDao;

	@Override
	@Transactional(readOnly = true)
	public List<Cargo> findAll() {
		return (List<Cargo>) cargoDao.findAll();
	}

	@Override
	@Transactional
	public void save(Cargo cargo) {
		cargoDao.save(cargo);
	}

	@Override
	@Transactional
	public void delete(Long codCargo) {
		cargoDao.deleteById(codCargo);
	}

	@Override
	@Transactional(readOnly = true)
	public Cargo findOne(Long codCargo) {
		return cargoDao.findById(codCargo).orElse(null);
	}

}
