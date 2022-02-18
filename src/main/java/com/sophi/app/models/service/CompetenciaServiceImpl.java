package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.ICompetenciasDao;
import com.sophi.app.models.entity.Competencias;

@Service
public class CompetenciaServiceImpl implements ICompetenciaService{
	
	@Autowired
	private ICompetenciasDao competenciasDao;

	@Override
	@Transactional(readOnly = true)
	public List<Competencias> findAll() {
		return (List<Competencias>) competenciasDao.findAll();
	}

	@Override
	@Transactional(readOnly = true)
	public Competencias findById(Long codCompetencias) {
		return competenciasDao.findById(codCompetencias).orElse(null);
	}

	@Override
	@Transactional(readOnly = true)
	public Competencias findByDescCompetencia(String descCompetencia) {
		return competenciasDao.findByDescCompetencias(descCompetencia);
	}

	@Override
	@Transactional
	public void guardar(Competencias competencia) {
		competenciasDao.save(competencia);
	}

	
	
	
}
