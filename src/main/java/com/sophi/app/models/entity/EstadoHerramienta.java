package com.sophi.app.models.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "CAT_ESTADO_HERRAMIENTA")
public class EstadoHerramienta implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Id
	@Column(name = "cod_estado_herramienta")
	private Long codEstadoHerramienta;
	
	@Column(name = "desc_estado_herramienta")
	private String descEstadoHerramienta;

	public Long getCodEstadoHerramienta() {
		return codEstadoHerramienta;
	}

	public void setCodEstadoHerramienta(Long codEstadoHerramienta) {
		this.codEstadoHerramienta = codEstadoHerramienta;
	}

	public String getDescEstadoHerramienta() {
		return descEstadoHerramienta;
	}

	public void setDescEstadoHerramienta(String descEstadoHerramienta) {
		this.descEstadoHerramienta = descEstadoHerramienta;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}
}
