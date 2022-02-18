package com.sophi.app.models.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "CAT_TIPO_CONOCIMIENTOS")
public class TipoConocimiento implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Id
	@Column(name = "cod_tipo_conocimiento")
	private Long codTipoConocimiento;
	
	@Column(name = "desc_tipo_conocimiento")
	private String descTipoConocimiento;

	public Long getCodTipoConocimiento() {
		return codTipoConocimiento;
	}

	public void setCodTipoConocimiento(Long codTipoConocimiento) {
		this.codTipoConocimiento = codTipoConocimiento;
	}

	public String getDescTipoConocimiento() {
		return descTipoConocimiento;
	}

	public void setDescTipoConocimiento(String descTipoConocimiento) {
		this.descTipoConocimiento = descTipoConocimiento;
	}

}
