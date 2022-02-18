package com.sophi.app.models.entity;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "CAT_AREAS_RECURSO")
public class AreaRecurso implements Serializable  {

	private static final long serialVersionUID = 1L;

	@Id
	@Column(name = "cod_consultor")
	private Long codConsultor;
	
	@Column(name = "desc_consultor")
	private String descConsultor;

	public Long getCodConsultor() {
		return codConsultor;
	}

	public void setCodConsultor(Long codConsultor) {
		this.codConsultor = codConsultor;
	}

	public String getDescConsultor() {
		return descConsultor;
	}

	public void setDescConsultor(String descConsultor) {
		this.descConsultor = descConsultor;
	}

	public static long getSerialversionuid() {
		return serialVersionUID;
	}
	
}
