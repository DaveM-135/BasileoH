package com.sophi.app.models.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "CAT_CLASIFICACION_PRESUPUESTO")
public class ClasificacionForecast implements Serializable  {

	private static final long serialVersionUID = 1L;

	@Id
	@Column(name = "id_clasificacion_presupuesto")
	private Long codClasificacionForecast;
	
	@Column(name = "desc_clasificacion_presupuesto")
	private String descClasificacionPresupuesto;
	
	@Column(name = "desc_clasificacion")
	private String descClasificacion;
	
	@Column(name = "val_forecast")
	private Long valForecast;

	public Long getCodClasificacionForecast() {
		return codClasificacionForecast;
	}

	public void setCodClasificacionForecast(Long codClasificacionForecast) {
		this.codClasificacionForecast = codClasificacionForecast;
	}

	public String getDescClasificacionPresupuesto() {
		return descClasificacionPresupuesto;
	}

	public void setDescClasificacionPresupuesto(String descClasificacionPresupuesto) {
		this.descClasificacionPresupuesto = descClasificacionPresupuesto;
	}

	public String getDescClasificacion() {
		return descClasificacion;
	}

	public void setDescClasificacion(String descClasificacion) {
		this.descClasificacion = descClasificacion;
	}

	public Long getValForecast() {
		return valForecast;
	}

	public void setValForecast(Long valForecast) {
		this.valForecast = valForecast;
	}

}
