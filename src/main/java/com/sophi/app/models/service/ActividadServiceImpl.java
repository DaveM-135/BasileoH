package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IActividadDao;
import com.sophi.app.models.entity.Actividad;

@Service
public class ActividadServiceImpl implements IActividadService {
	
	@Autowired
	private IActividadDao actividadDao;

	@Override
	@Transactional(readOnly = true)
	public List<Actividad> findAll() {
		return (List<Actividad>) actividadDao.findAll();
	}

	@Override
	@Transactional
	public void save(Actividad actividad) {
		actividadDao.save(actividad);
	}

	@Override
	@Transactional(readOnly = true)
	public Actividad findOne(Long codActividad) {
		return actividadDao.findById(codActividad).orElse(null);
	}

	@Override
	@Transactional
	public void delete(Actividad actividad) {
		actividadDao.delete(actividad);
	}

	@Override
	@Transactional
	public void saveAll(Iterable<Actividad> actividades) {
		actividadDao.saveAll(actividades);
	}

	@Override
	@Transactional(readOnly = true)
	public List<Long> findListaProyectoByRecurso(Long codRecurso) {
		return actividadDao.findListaProyectoByRecurso(codRecurso);
	}

	@Override
	@Transactional(readOnly = true)
	public List<Actividad> findListaActividadesByRecursoProyecto(Long codRecurso, Long codProyecto) {
		return actividadDao.findListaActividadesByRecursoProyecto(codRecurso, codProyecto);
	}

	@Override
	@Transactional(readOnly = true)
	public List<Actividad> findListaActividadesByRecursoProyectoPrimaria(Long codRecurso, Long codProyecto, String descPrimaria) {
		return actividadDao.findListaActividadesByRecursoProyectoPrimaria(codRecurso, codProyecto, descPrimaria);
	}

	@Override
	@Transactional(readOnly = true)
	public List<String> findListaActividadesPrimariasByRecursoProyecto(Long codRecurso, Long codProyecto) {
		return actividadDao.findListaActividadesPrimariasByRecursoProyecto(codRecurso, codProyecto);
	}

	@Override
	@Transactional(readOnly = true)
	public List<Actividad> findByCodRecurso(Long codRecurso) {
		return actividadDao.findByCodRecurso(codRecurso);
	}
	
	@Override
	@Transactional(readOnly = true)
	public long countByCodProyecto(Long codProyecto) {
		return actividadDao.countByCodProyecto(codProyecto);
	}

	@Override
	@Transactional(readOnly = true)
	public List<Actividad> findByCodProyecto(Long codProyecto) {
		return actividadDao.findByCodProyecto(codProyecto);
	}

	@Override
	@Transactional(readOnly = true)
	public Float sumTotalHorasProyecto(Long codRecurso, Long codProyecto) {
		return actividadDao.sumTotalHorasProyecto(codRecurso, codProyecto);
	}


}
