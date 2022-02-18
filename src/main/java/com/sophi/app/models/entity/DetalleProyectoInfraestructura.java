package com.sophi.app.models.entity;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;

@Entity
@Table(name = "DETALLE_PROYECTOS_INFRAESTRUCTURAS")
public class DetalleProyectoInfraestructura implements Serializable  {

	private static final long serialVersionUID = 1L;

	@EmbeddedId
    private DetalleProyectoInfraestructuraId detalleProyectoInfraestructuraId;
	
	@Column(name = "desc_version")
	private String descVersion;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	private Date fecRegistro;

	public DetalleProyectoInfraestructuraId getDetalleProyectoInfraestructuraId() {
		return detalleProyectoInfraestructuraId;
	}

	public void setDetalleProyectoInfraestructuraId(DetalleProyectoInfraestructuraId detalleProyectoInfraestructuraId) {
		this.detalleProyectoInfraestructuraId = detalleProyectoInfraestructuraId;
	}

	public String getDescVersion() {
		return descVersion;
	}

	public void setDescVersion(String descVersion) {
		this.descVersion = descVersion;
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
