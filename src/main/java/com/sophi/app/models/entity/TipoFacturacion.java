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
@Table(name = "CAT_TIPO_FACTURACION")
public class TipoFacturacion implements Serializable  {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_tipo_facturacion")
	private Long codTipoFacturacion;
	
	@Column(name = "desc_tipo_facturacion")
	private String 	descTipoFacturacion;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	private Date fecRegistro;

	public Long getCodTipoFacturacion() {
		return codTipoFacturacion;
	}

	public void setCodTipoFacturacion(Long codTipoFacturacion) {
		this.codTipoFacturacion = codTipoFacturacion;
	}

	public String getDescTipoFacturacion() {
		return descTipoFacturacion;
	}

	public void setDescTipoFacturacion(String descTipoFacturacion) {
		this.descTipoFacturacion = descTipoFacturacion;
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
