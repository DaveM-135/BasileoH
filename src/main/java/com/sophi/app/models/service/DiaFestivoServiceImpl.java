package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IDiaFestivoDao;
import com.sophi.app.models.entity.DiaFestivo;

@Service
public class DiaFestivoServiceImpl implements IDiaFestivoService {

	@Autowired
	private IDiaFestivoDao diaFestivoDao;
	
	@Override
	@Transactional(readOnly = true)
	public List<DiaFestivo> findAll() {
		return (List<DiaFestivo>) diaFestivoDao.findAll();
	}

	@Override
	@Transactional
	public void save(DiaFestivo diaFestivo) {
		diaFestivoDao.save(diaFestivo);
	}

	@Override
	@Transactional
	public void delete(Long codDiaFestivo) {
		diaFestivoDao.deleteById(codDiaFestivo);		
	}

	@Override
	@Transactional(readOnly = true)
	public List<DiaFestivo> findEsNoLaboral(Long codDiaFestivo) {
		return diaFestivoDao.findEsNoLaboral(codDiaFestivo);
	}

	@Override
	public List<DiaFestivo> findByCodDiaFestivoPorMes(Long inicioMes, Long finMes) {
		return diaFestivoDao.findByCodDiaFestivo(inicioMes, finMes);
	}

}
