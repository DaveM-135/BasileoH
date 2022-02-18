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
@Table(name = "CAT_AREAS_COMERCIALES")
public class AreaComercial implements Serializable  {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_area_comercial")
	private Long codAreaComercial;
	
	@Column(name = "desc_area_comercial")
	private String descAreaComercial;
	
	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	private Date fecRegistro;

	public Long getCodAreaComercial() {
		return codAreaComercial;
	}

	public void setCodAreaComercial(Long codAreaComercial) {
		this.codAreaComercial = codAreaComercial;
	}

	public String getDescAreaComercial() {
		return descAreaComercial;
	}

	public void setDescAreaComercial(String descAreaComercial) {
		this.descAreaComercial = descAreaComercial;
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
