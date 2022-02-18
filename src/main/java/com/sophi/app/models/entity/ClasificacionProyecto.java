package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@Entity
@Table(name = "CAT_CLASIFICACIONES_PROYECTO")
public class ClasificacionProyecto implements Serializable  {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_clasificacion_proyecto")
	private Long codClasificacionProyecto;
	
	@Column(name = "desc_clasificacion")
	private String 	descClasificacion;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	private Date fecRegistro;

	public Long getCodClasificacionProyecto() {
		return codClasificacionProyecto;
	}

	public void setCodClasificacionProyecto(Long codClasificacionProyecto) {
		this.codClasificacionProyecto = codClasificacionProyecto;
	}

	public String getDescClasificacion() {
		return descClasificacion;
	}

	public void setDescClasificacion(String descClasificacion) {
		this.descClasificacion = descClasificacion;
	}

	public Date getFecRegistro() {
		return fecRegistro;
	}

	public void setFecRegistro(Date fecRegistro) {
		this.fecRegistro = fecRegistro;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}
	
}
