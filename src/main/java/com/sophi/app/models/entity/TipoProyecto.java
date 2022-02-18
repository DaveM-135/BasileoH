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
@Table(name = "CAT_TIPO_PROYECTO")
public class TipoProyecto implements Serializable  {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_tipo_proyecto")
	private Long codTipoProyecto;
	
	@Column(name = "desc_tipo_proyecto")
	private String descTipoProyecto;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	private Date fecRegistro;

	public Long getCodTipoProyecto() {
		return codTipoProyecto;
	}

	public void setCodTipoProyecto(Long codTipoProyecto) {
		this.codTipoProyecto = codTipoProyecto;
	}

	public String getDescTipoProyecto() {
		return descTipoProyecto;
	}

	public void setDescTipoProyecto(String descTipoProyecto) {
		this.descTipoProyecto = descTipoProyecto;
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
