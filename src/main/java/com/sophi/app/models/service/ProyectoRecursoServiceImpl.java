package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IProyectoRecursoDao;
import com.sophi.app.models.entity.ProyectoRecurso;
import com.sophi.app.models.entity.ProyectoRecursoId;

@Service
public class ProyectoRecursoServiceImpl implements IProyectoRecursoService {
	
	@Autowired
	private IProyectoRecursoDao proyectoRecursoDao;

	@Override
	@Transactional(readOnly = true)
	public List<ProyectoRecurso> findAll() {
		return (List<ProyectoRecurso>) proyectoRecursoDao.findAll();
	}

	@Override
	@Transactional
	public void save(ProyectoRecurso proyectoRecurso) {
		proyectoRecursoDao.save(proyectoRecurso);
	}

	@Override
	@Transactional(readOnly = true)
	public ProyectoRecurso findOne(ProyectoRecursoId  proyectoRecursoId) {
		return proyectoRecursoDao.findById( proyectoRecursoId).orElse(null);
	}

	@Override
	@Transactional
	public void delete(ProyectoRecurso recursoGasto) {
		proyectoRecursoDao.delete(recursoGasto);
	}
	
	@Override
	@Transactional(readOnly = true)
	public List<ProyectoRecurso> findByProyectoRecursoIdCodRecurso(Long codRecurso) {
		return (List<ProyectoRecurso>) proyectoRecursoDao.findByProyectoRecursoIdCodRecurso(codRecurso);
	}

	@Override
	@Transactional
	public void saveAll(List<ProyectoRecurso> proyectoRecurso) {
		proyectoRecursoDao.saveAll(proyectoRecurso);
	}

	@Override
	@Transactional(readOnly = true)
	public List<ProyectoRecurso> findByProyectoRecursoIdCodProyecto(Long codProyecto) {
		return (List<ProyectoRecurso>) proyectoRecursoDao.findByProyectoRecursoIdCodProyecto(codProyecto);
	}

	@Override
	@Transactional(readOnly = true)
	public List<ProyectoRecurso> findProyectoRecursoActivo(Long codRecurso) {
		return proyectoRecursoDao.findProyectoRecursoActivo(codRecurso);
	}
	
}
