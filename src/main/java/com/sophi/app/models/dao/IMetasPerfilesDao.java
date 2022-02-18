package com.sophi.app.models.dao;

import javax.transaction.Transactional;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.MetasPerfiles;

public interface IMetasPerfilesDao extends CrudRepository<MetasPerfiles, Long>{
	
	@Modifying
	@Transactional
	@Query(value = "DELETE FROM CAT_METAS_PERFILES WHERE cod_perfil=?1", nativeQuery = true)
	public void deleteByCodPerfil(Long codPerfil);
	
}
