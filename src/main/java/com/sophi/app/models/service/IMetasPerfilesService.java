package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.MetasPerfiles;

public interface IMetasPerfilesService {
	
	public void guardarAll(List<MetasPerfiles> metasPerfil);
	
	public void deleteByCodPerfil(Long codPerfil);

}
