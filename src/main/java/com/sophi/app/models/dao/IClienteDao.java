package com.sophi.app.models.dao;

import org.springframework.data.repository.CrudRepository;

import com.sophi.app.models.entity.Cliente;

public interface IClienteDao extends CrudRepository<Cliente, Long> {

}
