package com.sophi.app.models.dao;

import java.util.List;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.Rol;

public interface IRolDao extends CrudRepository<Rol, Long>{
	
	@Query("FROM Rol r WHERE r.descRol = 'ROLE_LIDER'")
    List<Rol> findListaRoles();
	
	@Query("FROM Rol r WHERE r.cod_recurso = ?1")
	List<Rol> findByCodRecurso(Long cod_recurso);
	
	@Query(value="select distinct(u.desc_usuario) usuarios from ROLES r inner join USUARIOS u on r.cod_usuario = u.cod_usuario where r.desc_rol in ('ROLE_ADMIN','ROLE_RH')",nativeQuery = true)
	List<String> getListaAdminRh();

}
