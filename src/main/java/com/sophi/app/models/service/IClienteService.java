package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.Cliente;

public interface IClienteService {

	List<Cliente> listaClientes();
	
	public List<Cliente> findAll();
	
	public void save(Cliente cliente);
	
	public void delete(Long codCliente);
	
	public Cliente findOne(Long codCliente);
	
}
