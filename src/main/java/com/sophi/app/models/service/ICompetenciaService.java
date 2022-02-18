package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.Competencias;

public interface ICompetenciaService {

	public List<Competencias> findAll();
	
	public Competencias findById(Long codCompetencias);
	
	public Competencias findByDescCompetencia(String descCompetencia);
	
	public void guardar(Competencias competencia);
	
}
