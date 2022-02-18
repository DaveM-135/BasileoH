package com.sophi.app.models.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sophi.app.models.dao.IDetalleEvaluacionProyectoDao;
import com.sophi.app.models.entity.Concepto;
import com.sophi.app.models.entity.DetalleEvaluacionProyecto;

@Service
public class DetalleEvaluacionProyectoServiceImpl implements IDetalleEvaluacionProyectoService{
	
	@Autowired
	private IDetalleEvaluacionProyectoDao detalleEvaluacionProyectoDao;

	@Override
	@Transactional
	public void guardarDetalle(DetalleEvaluacionProyecto  detalleEvaluacionProyecto) {
		detalleEvaluacionProyectoDao.save(detalleEvaluacionProyecto);
	}

	@Override
	@Transactional(readOnly = true)
	public DetalleEvaluacionProyecto findById(Long codDetalleEvaluacion) {
		return detalleEvaluacionProyectoDao.findById(codDetalleEvaluacion).orElse(null);
	}

	@Override
	@Transactional(readOnly = true)
	public DetalleEvaluacionProyecto findByConceptoAndCodProyecto(Concepto concepto, Long codProyecto) {
		return detalleEvaluacionProyectoDao.findByConceptoAndCodProyecto(concepto, codProyecto);
	}

	@Override
	@Transactional(readOnly = true)
	public List<DetalleEvaluacionProyecto> findByCodProyecto(Long codProyecto) {
		return detalleEvaluacionProyectoDao.findByCodProyecto(codProyecto);
	}

	@Override
	@Transactional
	public void eliminarDetalle(Long codDetalle) {
		detalleEvaluacionProyectoDao.deleteById(codDetalle);
	}

	@Override
	@Transactional
	public void guardarTodosDetalle(List<DetalleEvaluacionProyecto> detallesEvaluacionProyecto) {
		detalleEvaluacionProyectoDao.saveAll(detallesEvaluacionProyecto);
	}

	@Override
	@Transactional(readOnly = true)
	public Integer conceptosNoEvaluadosByCodProyecto(Long codProyecto) {
		return detalleEvaluacionProyectoDao.conceptosNoEvaluadosByCodProyecto(codProyecto);
	}

}
