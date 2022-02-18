package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.ICompetenciasPerfilesDao;
import com.sophi.app.models.entity.CompetenciasPerfiles;

@Service
public class CompetenciasPerfilesServiceImpl implements ICompetenciasPerfilesService{
	
	@Autowired
	private ICompetenciasPerfilesDao competenciaPerfilDao;

	@Override
	@Transactional
	public void guardar(CompetenciasPerfiles competenciaPerfil) {
		competenciaPerfilDao.save(competenciaPerfil);
	}

	@Override
	@Transactional
	public void guardarAll(List<CompetenciasPerfiles> competenciasPerfil) {
		competenciaPerfilDao.saveAll(competenciasPerfil);
	}

	@Override
	@Transactional
	public void deleteByCodPerfil(Long codPerfil) {
		competenciaPerfilDao.deleteByCodPerfil(codPerfil);
	}

	@Override
	@Transactional(readOnly = true)
	public CompetenciasPerfiles findById(Long codCompetenciaPerfi) {
		return competenciaPerfilDao.findById(codCompetenciaPerfi).orElse(null);
	}

}
