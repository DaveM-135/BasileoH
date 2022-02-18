package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.CompetenciasPerfiles;

public interface ICompetenciasPerfilesService {

	public void guardar(CompetenciasPerfiles competenciaPerfil);
	
	public void guardarAll(List<CompetenciasPerfiles> competenciasPerfil);
	
	public void deleteByCodPerfil(Long codPerfil);
	
	public CompetenciasPerfiles findById(Long codCompetenciaPerfi);
	
}
