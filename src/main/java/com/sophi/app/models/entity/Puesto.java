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
@Table(name = "CAT_PUESTOS_EMPRESA")
public class Puesto implements Serializable {
	
	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "cod_puesto")
	private Long codPuesto;

	@Column(name = "desc_puesto")
	private String descPuesto;

	@Column(name = "fec_registro")
	@Temporal(TemporalType.TIMESTAMP)
	private Date fecRegistro;

	public Long getCodPuesto() {
		return codPuesto;
	}

	public void setCodPuesto(Long codPuesto) {
		this.codPuesto = codPuesto;
	}

	public String getDescPuesto() {
		return descPuesto;
	}

	public void setDescPuesto(String descPuesto) {
		this.descPuesto = descPuesto;
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
