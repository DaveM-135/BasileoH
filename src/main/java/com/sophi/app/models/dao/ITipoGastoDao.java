package com.sophi.app.models.dao;

import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.TipoGasto;

public interface ITipoGastoDao extends CrudRepository<TipoGasto, Long> {

}
