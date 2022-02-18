package com.sophi.app.models.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "CAT_TIPO_HERRAMIENTA")
public class TipoHerramienta implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Id
	@Column(name = "cod_tipo_herramienta")
	private Long codTipoHerramienta;
	
	@Column(name = "desc_tipo_herramienta")
	private String descTipoHerramienta;

	public Long getCodTipoHerramienta() {
		return codTipoHerramienta;
	}

	public void setCodTipoHerramienta(Long codTipoHerramienta) {
		this.codTipoHerramienta = codTipoHerramienta;
	}

	public String getDescTipoHerramienta() {
		return descTipoHerramienta;
	}

	public void setDescTipoHerramienta(String descTipoHerramienta) {
		this.descTipoHerramienta = descTipoHerramienta;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}
}
