package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IEquipoDao;
import com.sophi.app.models.entity.Equipo;

@Service
public class EquipoImpl implements IEquipoService {

	@Autowired
	private IEquipoDao equipoDao;
	
	@Override
	@Transactional(readOnly = true)
	public List<Equipo> findAll(){
		return (List<Equipo>) equipoDao.findAll();
	}

	@Override
	@Transactional(readOnly = true)
	public Equipo findByCodEstadoHerramienta(Long codEstadoHerramienta) {
		return equipoDao.findByCodEstadoHerramienta(codEstadoHerramienta);
	}
	
	@Override
	@Transactional(readOnly = true)
	public List<Equipo> findByCodTipoHerramienta(Long codTipoHerramienta) {
		return (List<Equipo>) equipoDao.findByCodTipoHerramienta(codTipoHerramienta);
	}
	
	@Override
	@Transactional(readOnly = true)
	public Equipo findByCodHerramienta(Long codHerramienta) {
		return equipoDao.findByCodHerramienta(codHerramienta);
	}

	@Override
	@Transactional(readOnly = true)
	public List<Equipo> findListEquiposDisponibles() {
		return equipoDao.findListEquiposDisponibles();
	}

	@Override
	public List<Equipo> findListEquiposDisponiblesPorTipoHerramienta(Long codTipoHerramienta) {
		return equipoDao.findListEquiposDisponiblesPorTipoHerramienta(codTipoHerramienta);
	}

}
