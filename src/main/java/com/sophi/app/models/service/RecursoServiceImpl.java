package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IRecursoDao;
import com.sophi.app.models.entity.Recurso;
import com.sophi.app.models.entity.RecursoIdNombre;

@Service
public class RecursoServiceImpl implements IRecursoService {

	@Autowired
	private IRecursoDao recursoDao;
	
	@Override
	@Transactional(readOnly = true)
	public List<Recurso> findAll() {
		return (List<Recurso>) recursoDao.findAll();
	}

	@Override
	@Transactional
	public void save(Recurso recurso) {
		recursoDao.save(recurso);
	}

	@Override
	@Transactional(readOnly = true)
	public Recurso findOne(Long codRecurso) {
//		return recursoDao.findById(codRecurso).orElse(null);
		return recursoDao.findByCodRecurso(codRecurso);
	}

	@Override
	@Transactional(readOnly = true)
	public List<Recurso> findByNombreApellido(String descRecurso, String descApellidoPaterno) {
		return recursoDao.findByNombreApellido(descRecurso, descApellidoPaterno);
	}

	@Override
	@Transactional(readOnly = true)
	public List<Recurso> listaRecursos() {
		return (List<Recurso>) recursoDao.findAll();
	}

	@Override
	@Transactional(readOnly = true)
	public Recurso findByDescCorreoElectronico(String correoElectronico) {
		return recursoDao.findByDescCorreoElectronico(correoElectronico);
	}

	@Override
	@Transactional(readOnly = true)
	public List<Recurso> findRecursosActivos() {
		return recursoDao.findRecursosActivos();
	}

	@Override
	@Transactional(readOnly = true)
	public List<Recurso> findListRecursosResponsables() {
		return recursoDao.findListRecursosResponsables();
	}

	@Override
	@Transactional(readOnly = true)
	public List<Recurso> findListRecursosAprobadores() {
		return recursoDao.findListRecursosAprobadores();
	}
	
	@Override
	@Transactional(readOnly = true)
	public List<Recurso> findListRecursosAprobadoresBKP(Long codRecurso) {
		return recursoDao.findListRecursosAprobadoresBKP(codRecurso);
	}

	@Override
	@Transactional(readOnly = true)
	public List<Recurso> findByCodAreaRecurso(Long codAreaRecurso) {
		return recursoDao.findByCodAreaRecurso(codAreaRecurso);
	}

	@Override
	@Transactional(readOnly = true)
	public List<Recurso> findRecursosByPerfil(Long codPerfil) {
		return recursoDao.findRecursosByPerfil(codPerfil);
	}

	@Override
	@Transactional(readOnly = true)
	public List<RecursoIdNombre> findActivosOnlyIdNombre() {
		return recursoDao.recursosActivosOnlyIdNombre();
	}

	@Override
	@Transactional(readOnly = true)
	public String getNombreApellidoById(Long codRecurso) {
		return recursoDao.getNombreApellidoById(codRecurso);
	}

	@Override
	@Transactional(readOnly = true)
	public String getEmailRecursoById(Long codRecurso) {
		return recursoDao.getEmailRecursoById(codRecurso);
	}

	@Override
	@Transactional(readOnly = true)
	public String getNombreApellidoPuestoById(Long codRecurso) {
		return recursoDao.getNombreApellidoPuestoById(codRecurso);
	}
	
	

	
}
