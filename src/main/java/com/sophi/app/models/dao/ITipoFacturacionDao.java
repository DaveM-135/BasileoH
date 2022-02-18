package com.sophi.app.models.dao;


import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.TipoFacturacion;

public interface ITipoFacturacionDao  extends CrudRepository<TipoFacturacion, Long> {
	

}
