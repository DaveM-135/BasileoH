package com.sophi.app.models.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.persistence.Id;

@Entity
@Table(name = "CAT_ESTADO_CIVIL")
public class EstadoCivil implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Id
	@Column(name = "cod_estado_civil")
	private Long codEstadoCivil;
	
	@Column(name = "desc_estado_civil")
	private String descEstadoCivil;

	public Long getCodEstadoCivil() {
		return codEstadoCivil;
	}

	public void setCodEstadoCivil(Long codEstadoCivil) {
		this.codEstadoCivil = codEstadoCivil;
	}

	public String getDescEstadoCivil() {
		return descEstadoCivil;
	}

	public void setDescEstadoCivil(String descEstadoCivil) {
		this.descEstadoCivil = descEstadoCivil;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}
}
