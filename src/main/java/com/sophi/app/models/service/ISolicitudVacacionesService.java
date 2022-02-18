package com.sophi.app.models.service;

import java.util.List;

import com.sophi.app.models.entity.SolicitudVacaciones;

public interface ISolicitudVacacionesService {
	
	public SolicitudVacaciones findById(Long codSolicitudVacaciones);
	
	public List<SolicitudVacaciones> findByCodRecurso(Long codRecurso);
	
	public void save(SolicitudVacaciones solicitud);
	
	public void delete(SolicitudVacaciones solicitud);

}
